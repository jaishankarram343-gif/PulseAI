const express=require('express'),path=require('path'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),DB=require('better-sqlite3');
const app=express(),db=new DB(process.env.DB_PATH||'pulseai.sqlite'),PORT=process.env.PORT||3000,SECRET=process.env.JWT_SECRET||'CHANGE_ME';
app.set('trust proxy',1);
db.pragma('journal_mode=WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT,
 email TEXT UNIQUE,
 password TEXT,
 created TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS accounts(
 user_id INTEGER PRIMARY KEY,
 cash REAL DEFAULT 1000,
 realized REAL DEFAULT 0,
 daily_loss REAL DEFAULT 0,
 auto_trade INTEGER DEFAULT 1,
 risk REAL DEFAULT 1,
 sl REAL DEFAULT 1,
 tp REAL DEFAULT 2,
 min_score INTEGER DEFAULT 65
);

CREATE TABLE IF NOT EXISTS positions(
 user_id INTEGER PRIMARY KEY,
 symbol TEXT,
 side TEXT,
 entry REAL,
 qty REAL,
 fee REAL,
 opened TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS trades(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER,
 symbol TEXT,
 side TEXT,
 entry REAL,
 exit REAL,
 qty REAL,
 pnl REAL,
 reason TEXT,
 created TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

app.use(express.json({limit:'100kb'}));
app.use(express.static(path.join(__dirname,'public')));

app.get('/health',(q,r)=>r.json({ok:true,service:'PulseAI',version:'v5'}));

const user=id=>db.prepare(
 'SELECT id,name,email,created FROM users WHERE id=?'
).get(id);

const acct=id=>db.prepare(
 'SELECT * FROM accounts WHERE user_id=?'
).get(id);

const auth=(q,r,n)=>{
 try{
  let h=q.headers.authorization||'';
  q.user=jwt.verify(h.replace('Bearer ',''),SECRET);
  n();
 }catch(e){
  r.status(401).json({error:'Login required'});
 }
};

app.post('/api/signup',(q,r)=>{
 let {name,email,password}=q.body||{};
 name=String(name||'').trim();
 email=String(email||'').trim().toLowerCase();

 if(name.length<2||!email.includes('@')||String(password||'').length<8)
  return r.status(400).json({error:'Enter name, valid email and 8+ character password'});

 try{
  let id=db.prepare(
   'INSERT INTO users(name,email,password) VALUES(?,?,?)'
  ).run(name,email,bcrypt.hashSync(password,12)).lastInsertRowid;

  db.prepare('INSERT INTO accounts(user_id) VALUES(?)').run(id);

  let u=user(id);

  r.json({
   token:jwt.sign({id},SECRET,{expiresIn:'7d'}),
   user:u,
   account:acct(id)
  });
  }catch(e){
  console.error('SIGNUP ERROR:', e);
  r.status(500).json({error:e.message});
 }
});

app.post('/api/login',(q,r)=>{
 let email=String(q.body.email||'').trim().toLowerCase();
 let u=db.prepare('SELECT * FROM users WHERE email=?').get(email);

 if(!u||!bcrypt.compareSync(String(q.body.password||''),u.password))
  return r.status(401).json({error:'Invalid email or password'});

 r.json({
  token:jwt.sign({id:u.id},SECRET,{expiresIn:'7d'}),
  user:user(u.id),
  account:acct(u.id)
 });
});

app.get('/api/me',auth,(q,r)=>{
 r.json({
  user:user(q.user.id),
  account:acct(q.user.id),
  position:db.prepare(
   'SELECT * FROM positions WHERE user_id=?'
  ).get(q.user.id)
 });
});

app.get('/api/trades',auth,(q,r)=>{
 r.json({
  trades:db.prepare(
   'SELECT * FROM trades WHERE user_id=? ORDER BY id DESC LIMIT 100'
  ).all(q.user.id)
 });
});

app.post('/api/settings',auth,(q,r)=>{
 let b=q.body,a=acct(q.user.id);

 db.prepare(`
  UPDATE accounts
  SET auto_trade=?,risk=?,sl=?,tp=?,min_score=?
  WHERE user_id=?
 `).run(
  b.auto_trade?1:0,
  Number(b.risk??a.risk),
  Number(b.sl??a.sl),
  Number(b.tp??a.tp),
  Number(b.min_score??a.min_score),
  q.user.id
 );

 r.json({account:acct(q.user.id)});
});

app.post('/api/paper/open',auth,(q,r)=>{
 let a=acct(q.user.id),b=q.body,p=Number(b.price);

 if(db.prepare('SELECT 1 FROM positions WHERE user_id=?').get(q.user.id))
  return r.status(409).json({error:'Position already open'});

 if(!p||p<=0)
  return r.status(400).json({error:'Invalid price'});

 let risk=a.cash*a.risk/100;
 let qty=risk/(p*a.sl/100);
 let notional=qty*p;
 let fee=notional*.001;

 if(notional+fee>a.cash){
  qty=(a.cash-fee)/p;
  notional=qty*p;
  fee=notional*.001;
 }

 db.prepare(
  'UPDATE accounts SET cash=cash-? WHERE user_id=?'
 ).run(notional+fee,q.user.id);

 db.prepare(`
  INSERT INTO positions(user_id,symbol,side,entry,qty,fee)
  VALUES(?,?,?,?,?,?)
 `).run(q.user.id,b.symbol,b.side,p,qty,fee);

 r.json({
  account:acct(q.user.id),
  position:db.prepare(
   'SELECT * FROM positions WHERE user_id=?'
  ).get(q.user.id)
 });
});

app.post('/api/paper/close',auth,(q,r)=>{
 let p=db.prepare(
  'SELECT * FROM positions WHERE user_id=?'
 ).get(q.user.id);

 let price=Number(q.body.price);

 if(!p)
  return r.status(409).json({error:'No open position'});

 let d=p.side==='LONG'?1:-1;
 let n=price*p.qty;
 let ef=n*.001;
 let pnl=(price-p.entry)*p.qty*d-p.fee-ef;

 db.transaction(()=>{
  db.prepare(`
   UPDATE accounts
   SET cash=cash+?,realized=realized+?,daily_loss=daily_loss+?
   WHERE user_id=?
  `).run(
   n-ef,
   pnl,
   pnl<0?-pnl:0,
   q.user.id
  );

  db.prepare(`
   INSERT INTO trades(user_id,symbol,side,entry,exit,qty,pnl,reason)
   VALUES(?,?,?,?,?,?,?,?)
  `).run(
   q.user.id,
   p.symbol,
   p.side,
   p.entry,
   price,
   p.qty,
   pnl,
   q.body.reason||'Manual'
  );

  db.prepare(
   'DELETE FROM positions WHERE user_id=?'
  ).run(q.user.id);
 })();

 r.json({account:acct(q.user.id)});
});

app.post('/api/reset',auth,(q,r)=>{
 db.transaction(()=>{
  db.prepare('DELETE FROM positions WHERE user_id=?').run(q.user.id);
  db.prepare('DELETE FROM trades WHERE user_id=?').run(q.user.id);

  db.prepare(`
   UPDATE accounts
   SET cash=1000,realized=0,daily_loss=0
   WHERE user_id=?
  `).run(q.user.id);
 })();

 r.json({account:acct(q.user.id)});
});

app.get('*',(q,r)=>{
 r.sendFile(path.join(__dirname,'public/index.html'));
});

app.listen(PORT,'0.0.0.0',()=>{
 console.log('PulseAI v5 running on port '+PORT);
});
