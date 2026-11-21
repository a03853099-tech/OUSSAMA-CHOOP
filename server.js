const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const TOKEN_SECRET = process.env.TOKEN_SECRET;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data.sqlite");

if (!ADMIN_PASSWORD || !TOKEN_SECRET) {
  console.error("Set ADMIN_PASSWORD and TOKEN_SECRET environment variables before starting.");
  process.exit(1);
}

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS players (
 id TEXT PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE,
 token TEXT NOT NULL UNIQUE, points INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL, last_seen INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS answers (
 player_id TEXT NOT NULL, day TEXT NOT NULL, q_index INTEGER NOT NULL,
 correct INTEGER NOT NULL, PRIMARY KEY(player_id, day, q_index)
);
CREATE TABLE IF NOT EXISTS logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL,
 action TEXT NOT NULL, player TEXT NOT NULL, detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS claims (
 id TEXT PRIMARY KEY, player_id TEXT NOT NULL, player_name TEXT NOT NULL,
 reward TEXT NOT NULL, cost INTEGER NOT NULL, status TEXT NOT NULL,
 created_at TEXT NOT NULL
);
`);

const questions = [
 {q:"شنو اسم العملة الرئيسية المعروفة فـ Free Fire لشراء بعض العناصر؟", a:["الذهب","الدايموند","الخشب"], correct:1, why:"الدايموند من العملات المعروفة في اللعبة."},
 {q:"شنو اسم المنطقة الآمنة اللي خاص اللاعب يبقى داخلها؟", a:["الزون","المتجر","اللوبي"], correct:0, why:"الزون هي المنطقة الآمنة."},
 {q:"شحال عدد الصلوات المفروضة في اليوم والليلة؟", a:["3","5","7"], correct:1, why:"الصلوات المفروضة خمس."},
 {q:"شنو هو الشهر اللي كيصومو فيه المسلمون؟", a:["شعبان","رمضان","محرم"], correct:1, why:"الصيام المفروض كيكون في شهر رمضان."},
 {q:"شنو هي قبلة المسلمين في الصلاة؟", a:["المسجد الأقصى","الكعبة","المسجد النبوي"], correct:1, why:"قبلة المسلمين هي الكعبة المشرفة."}
];
const rewards = [
 {name:"حساب فري فاير",cost:100,desc:"حساب Free Fire"},
 {name:"حساب أمريكي",cost:50,desc:"حساب أمريكي"},
 {name:"زيت فري فاير",cost:50,desc:"زيت فري فاير"},
 {name:"فيزة أمريكية",cost:35,desc:"فيزة أمريكية"}
];

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: true } });
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({limit:"30kb"}));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api", rateLimit({windowMs:60*1000, max:180, standardHeaders:true, legacyHeaders:false}));

const nowText = () => new Date().toLocaleString("ar-MA", {timeZone:"Africa/Casablanca"});
const dayKey = () => new Intl.DateTimeFormat("en-CA", {timeZone:"Africa/Casablanca"}).format(new Date());
const id = () => crypto.randomUUID();
const hashToken = s => crypto.createHash("sha256").update(s).digest("hex");
function sign(payload) {
 const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
 const sig = crypto.createHmac("sha256", TOKEN_SECRET).update(body).digest("base64url");
 return body + "." + sig;
}
function verifySigned(token) {
 try {
  const [body,sig] = token.split(".");
  const expected = crypto.createHmac("sha256", TOKEN_SECRET).update(body).digest("base64url");
  if (!sig || !crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected))) return null;
  const p = JSON.parse(Buffer.from(body,"base64url").toString());
  return p.exp > Date.now() ? p : null;
 } catch { return null; }
}
function playerAuth(req,res,next) {
 const token=(req.headers.authorization||"").replace(/^Bearer\s+/i,"");
 if(!token) return res.status(401).json({error:"خاصك تسجل الدخول."});
 const player=db.prepare("SELECT id,name,points,created_at,last_seen FROM players WHERE token=?").get(hashToken(token));
 if(!player) return res.status(401).json({error:"جلسة اللاعب غير صالحة، عاود التسجيل."});
 req.player=player; req.rawToken=token; next();
}
function adminAuth(req,res,next) {
 const token=(req.headers.authorization||"").replace(/^Bearer\s+/i,"");
 const p=verifySigned(token);
 if(!p || p.role!=="admin") return res.status(401).json({error:"خاصك تدخل للإدارة."});
 next();
}
function log(action, player, detail="") {
 db.prepare("INSERT INTO logs(at,action,player,detail) VALUES(?,?,?,?)").run(nowText(),action,player,detail);
}
function broadcast() { io.emit("data_changed", {at:Date.now()}); }
function playerView(p) {
 return {id:p.id,name:p.name,points:p.points,created:p.created_at,lastSeen:p.last_seen};
}
app.get("/api/config",(req,res)=>res.json({questions:questions.map(({q,a,why})=>({q,a,why})),rewards,whatsapp:"212696240414"}));

app.post("/api/register",(req,res)=>{
 const name=String(req.body.name||"").trim();
 if(name.length<2 || name.length>30) return res.status(400).json({error:"الاسم خاصو يكون بين 2 و30 حرف."});
 const exists=db.prepare("SELECT id FROM players WHERE name=? COLLATE NOCASE").get(name);
 if(exists) return res.status(409).json({error:"هاد الاسم مسجل من قبل. استعمل نفس الهاتف اللي تسجلتي به."});
 const playerId=id(), token=crypto.randomBytes(32).toString("hex"), stamp=nowText();
 db.prepare("INSERT INTO players(id,name,token,points,created_at,last_seen) VALUES(?,?,?,?,?,?)")
   .run(playerId,name,hashToken(token),0,stamp,Date.now());
 log("تسجيل لاعب",name,"تسجيل جديد");
 broadcast();
 res.json({token,player:{id:playerId,name,points:0,created:stamp}});
});
app.get("/api/me",playerAuth,(req,res)=>{
 db.prepare("UPDATE players SET last_seen=? WHERE id=?").run(Date.now(),req.player.id);
 const p=db.prepare("SELECT * FROM players WHERE id=?").get(req.player.id);
 res.json({player:playerView(p),day:dayKey()});
});
app.post("/api/heartbeat",playerAuth,(req,res)=>{
 db.prepare("UPDATE players SET last_seen=? WHERE id=?").run(Date.now(),req.player.id);
 res.json({ok:true});
});
app.get("/api/leaderboard",playerAuth,(req,res)=>{
 const rows=db.prepare("SELECT id,name,points FROM players ORDER BY points DESC, name COLLATE NOCASE ASC LIMIT 100").all();
 res.json({players:rows});
});
app.get("/api/tasks",playerAuth,(req,res)=>{
 const rows=db.prepare("SELECT q_index,correct FROM answers WHERE player_id=? AND day=?").all(req.player.id,dayKey());
 const answered={}; rows.forEach(r=>answered[r.q_index]=!!r.correct);
 res.json({questions:questions.map(({q,a,why})=>({q,a,why})),answered});
});
app.post("/api/answer",playerAuth,(req,res)=>{
 const index=Number(req.body.index), choice=Number(req.body.choice);
 if(!Number.isInteger(index)||index<0||index>=questions.length||!Number.isInteger(choice)||choice<0||choice>2)
   return res.status(400).json({error:"الجواب غير صالح."});
 try {
  const correct=choice===questions[index].correct;
  db.prepare("INSERT INTO answers(player_id,day,q_index,correct) VALUES(?,?,?,?)").run(req.player.id,dayKey(),index,correct?1:0);
  if(correct) db.prepare("UPDATE players SET points=points+1 WHERE id=?").run(req.player.id);
  log(correct?"نقطة مهمة يومية":"جواب غير صحيح",req.player.name,correct?"+1 سؤال "+(index+1):"السؤال "+(index+1));
  broadcast();
  res.json({correct,why:questions[index].why,player:playerView(db.prepare("SELECT * FROM players WHERE id=?").get(req.player.id))});
 } catch(e) {
  if(String(e).includes("UNIQUE")) return res.status(409).json({error:"جاوبتي على هاد السؤال اليوم من قبل."});
  throw e;
 }
});
app.post("/api/claim",playerAuth,(req,res)=>{
 const index=Number(req.body.rewardIndex), reward=rewards[index];
 if(!reward) return res.status(400).json({error:"الجائزة غير موجودة."});
 const p=db.prepare("SELECT * FROM players WHERE id=?").get(req.player.id);
 if(p.points<reward.cost) return res.status(400).json({error:"النقاط ديالك ما كافياش لهاد الجائزة."});
 const claimId=id();
 const tx=db.transaction(()=>{
  db.prepare("UPDATE players SET points=points-? WHERE id=?").run(reward.cost,p.id);
  db.prepare("INSERT INTO claims(id,player_id,player_name,reward,cost,status,created_at) VALUES(?,?,?,?,?,?,?)")
    .run(claimId,p.id,p.name,reward.name,reward.cost,"طلب جديد",nowText());
  log("طلب جائزة",p.name,reward.name+" ("+reward.cost+" نقطة)");
 });
 tx(); broadcast();
 res.json({ok:true,claimId,reward:reward.name,cost:reward.cost,whatsapp:"212696240414",player:playerView(db.prepare("SELECT * FROM players WHERE id=?").get(p.id))});
});

app.post("/api/admin/login",(req,res)=>{
 const given=String(req.body.password||"");
 const a=Buffer.from(given), b=Buffer.from(ADMIN_PASSWORD);
 if(a.length!==b.length || !crypto.timingSafeEqual(a,b)) return res.status(401).json({error:"كلمة السر غير صحيحة."});
 res.json({token:sign({role:"admin",exp:Date.now()+8*60*60*1000})});
});
app.get("/api/admin/overview",adminAuth,(req,res)=>{
 const players=db.prepare("SELECT * FROM players ORDER BY points DESC,name COLLATE NOCASE").all().map(p=>({
  ...playerView(p),online:Date.now()-p.last_seen<90000
 }));
 const claims=db.prepare("SELECT * FROM claims ORDER BY created_at DESC LIMIT 100").all();
 const logs=db.prepare("SELECT * FROM logs ORDER BY id DESC LIMIT 200").all();
 res.json({players,claims,logs,totalPoints:players.reduce((s,p)=>s+p.points,0)});
});
app.post("/api/admin/points",adminAuth,(req,res)=>{
 const pid=String(req.body.playerId||""), amount=Number(req.body.amount);
 if(!Number.isInteger(amount)||amount===0||Math.abs(amount)>100000) return res.status(400).json({error:"قيمة النقاط غير صالحة."});
 const p=db.prepare("SELECT * FROM players WHERE id=?").get(pid);
 if(!p)return res.status(404).json({error:"اللاعب غير موجود."});
 if(p.points+amount<0)return res.status(400).json({error:"النقاط مايمكنش تكون سالبة."});
 db.prepare("UPDATE players SET points=points+? WHERE id=?").run(amount,pid);
 log("تعديل النقاط",p.name,(amount>0?"+":"")+amount+" نقطة");broadcast();res.json({ok:true});
});
app.post("/api/admin/rename",adminAuth,(req,res)=>{
 const pid=String(req.body.playerId||""), name=String(req.body.name||"").trim();
 if(name.length<2||name.length>30)return res.status(400).json({error:"الاسم غير صالح."});
 try {const p=db.prepare("SELECT name FROM players WHERE id=?").get(pid);if(!p)return res.status(404).json({error:"اللاعب غير موجود."});
 db.prepare("UPDATE players SET name=? WHERE id=?").run(name,pid);log("تعديل الاسم",name,"الاسم السابق: "+p.name);broadcast();res.json({ok:true});}
 catch(e){if(String(e).includes("UNIQUE"))return res.status(409).json({error:"الاسم مستعمل من قبل."});throw e;}
});
app.delete("/api/admin/player/:id",adminAuth,(req,res)=>{
 const p=db.prepare("SELECT name FROM players WHERE id=?").get(req.params.id);if(!p)return res.status(404).json({error:"غير موجود."});
 db.prepare("DELETE FROM answers WHERE player_id=?").run(req.params.id);
 db.prepare("DELETE FROM claims WHERE player_id=?").run(req.params.id);
 db.prepare("DELETE FROM players WHERE id=?").run(req.params.id);
 log("حذف لاعب",p.name);broadcast();res.json({ok:true});
});
app.post("/api/admin/add-player",adminAuth,(req,res)=>{
 const name=String(req.body.name||"").trim(), points=Number(req.body.points||0);
 if(name.length<2||name.length>30||!Number.isInteger(points)||points<0||points>100000)return res.status(400).json({error:"المعلومات غير صالحة."});
 const pid=id(),token=crypto.randomBytes(32).toString("hex"),stamp=nowText();
 try{db.prepare("INSERT INTO players(id,name,token,points,created_at,last_seen) VALUES(?,?,?,?,?,?)").run(pid,name,hashToken(token),points,stamp,0);}
 catch{return res.status(409).json({error:"الاسم مسجل من قبل."});}
 log("إضافة من الإدارة",name,"+"+points+" نقطة");broadcast();res.json({ok:true});
});
app.post("/api/admin/claim-status",adminAuth,(req,res)=>{
 const claimId=String(req.body.claimId||""),status=String(req.body.status||"");
 if(!["تم التسليم","قيد المعالجة","مرفوض"].includes(status))return res.status(400).json({error:"الحالة غير صالحة."});
 const c=db.prepare("SELECT * FROM claims WHERE id=?").get(claimId);if(!c)return res.status(404).json({error:"الطلب غير موجود."});
 const tx=db.transaction(()=>{
  if(status==="مرفوض"&&c.status!=="مرفوض")db.prepare("UPDATE players SET points=points+? WHERE id=?").run(c.cost,c.player_id);
  db.prepare("UPDATE claims SET status=? WHERE id=?").run(status,claimId);
  log("تحديث طلب جائزة",c.player_name,c.reward+" - "+status);
 });tx();broadcast();res.json({ok:true});
});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

io.on("connection", socket=>socket.emit("connected",{ok:true}));
server.listen(PORT,()=>console.log("Ibrahim Osama server listening on "+PORT));
