require('dotenv').config();
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined
});
const PORT = process.env.PORT || 3000;
const PASS_PERCENT = 70;

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  store: new pgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  name: 'profrost.sid',
  secret: process.env.SESSION_SECRET || 'change-this-secret-before-deployment',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 }
}));
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, limit: 250, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(path.join(__dirname, 'public')));

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'student',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS tests (
      id SERIAL PRIMARY KEY, title TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'Общие',
      description TEXT NOT NULL DEFAULT '', access_type TEXT NOT NULL DEFAULT 'open',
      duration_minutes INTEGER NOT NULL DEFAULT 20, pass_percent INTEGER NOT NULL DEFAULT 70,
      questions JSONB NOT NULL DEFAULT '[]'::jsonb, active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS assignments (
      id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      test_id INTEGER NOT NULL REFERENCES tests(id) ON DELETE CASCADE,
      assigned_by INTEGER REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, test_id)
    );
    CREATE TABLE IF NOT EXISTS attempts (
      id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      test_id INTEGER NOT NULL REFERENCES tests(id) ON DELETE CASCADE,
      score INTEGER NOT NULL, total INTEGER NOT NULL, percent INTEGER NOT NULL,
      passed BOOLEAN NOT NULL, answers JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  const email = (process.env.ADMIN_EMAIL || 'admin@profrost-pv.kz').toLowerCase();
  const exists = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
  if (!exists.rowCount) {
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'ChangeMe123!', 12);
    await pool.query("INSERT INTO users(name,email,password_hash,role) VALUES($1,$2,$3,'admin')",
      [process.env.ADMIN_NAME || 'Администратор', email, hash]);
  }
  const count = await pool.query('SELECT COUNT(*)::int AS n FROM tests');
  if (!count.rows[0].n) {
    const sample = [
      { prompt: 'Что отражает бухгалтерский баланс?', options: ['Доходы и расходы за день','Активы, обязательства и капитал на дату','Только движение денежных средств','Список сотрудников'], correct: 1 },
      { prompt: 'Что относится к активам организации?', options: ['Кредиторская задолженность','Уставный капитал','Денежные средства на счёте','Нераспределённая прибыль'], correct: 2 },
      { prompt: 'Для чего применяется первичный документ?', options: ['Для подтверждения факта хозяйственной операции','Для утверждения отпуска','Для расчёта рейтинга сотрудников','Для составления рекламы'], correct: 0 },
      { prompt: 'Что такое дебиторская задолженность?', options: ['Долг организации поставщикам','Долг покупателей и других лиц организации','Сумма уставного капитала','Остаток материалов на складе'], correct: 1 },
      { prompt: 'Какой документ обычно подтверждает оплату?', options: ['Платёжное поручение или чек','Штатное расписание','Табель рабочего времени','Должностная инструкция'], correct: 0 }
    ];
    await pool.query(`INSERT INTO tests(title,category,description,access_type,duration_minutes,questions)
      VALUES($1,$2,$3,'open',15,$4::jsonb)`,
      ['Основы бухгалтерского учёта','Бухгалтерия','Демонстрационный открытый тест. Администратор может изменить или удалить его.', JSON.stringify(sample)]);
  }
}
const publicUser = u => ({ id: u.id, name: u.name, email: u.email, role: u.role });
function requireAuth(req,res,next){ if(!req.session.user) return res.status(401).json({error:'Войдите в систему'}); next(); }
function requireAdmin(req,res,next){ if(!req.session.user || req.session.user.role!=='admin') return res.status(403).json({error:'Доступ только для администратора'}); next(); }

app.get('/api/health', (req,res)=>res.json({ok:true, app:'ПрофРост-PV'}));
app.get('/api/me', (req,res)=>res.json({user:req.session.user || null, center:process.env.CENTER_NAME || 'ПрофРост-PV'}));

app.post('/api/register', async (req,res)=>{
  try {
    const name=String(req.body.name||'').trim(), email=String(req.body.email||'').trim().toLowerCase(), password=String(req.body.password||'');
    if(name.length<3 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length<8)
      return res.status(400).json({error:'Введите ФИО, корректный email и пароль не короче 8 символов'});
    const hash=await bcrypt.hash(password,12);
    const r=await pool.query("INSERT INTO users(name,email,password_hash,role) VALUES($1,$2,$3,'student') RETURNING id,name,email,role",
      [name,email,hash]);
    req.session.user=publicUser(r.rows[0]); res.json({user:req.session.user});
  } catch(e){ res.status(409).json({error:'Пользователь с таким email уже зарегистрирован'}); }
});
app.post('/api/login', async (req,res)=>{
  const email=String(req.body.email||'').toLowerCase(), r=await pool.query('SELECT * FROM users WHERE email=$1',[email]);
  if(!r.rowCount || !(await bcrypt.compare(String(req.body.password||''),r.rows[0].password_hash)))
    return res.status(401).json({error:'Неверный email или пароль'});
  req.session.user=publicUser(r.rows[0]); res.json({user:req.session.user});
});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get('/api/tests',requireAuth,async(req,res)=>{
  const r=await pool.query(`
    SELECT t.id,t.title,t.category,t.description,t.access_type,t.duration_minutes,t.pass_percent,
      jsonb_array_length(t.questions) AS question_count,
      EXISTS(SELECT 1 FROM assignments a WHERE a.test_id=t.id AND a.user_id=$1) AS assigned,
      (SELECT jsonb_build_object('id',at.id,'percent',at.percent,'passed',at.passed,'created_at',at.created_at)
       FROM attempts at WHERE at.test_id=t.id AND at.user_id=$1 ORDER BY at.id DESC LIMIT 1) AS last_attempt
    FROM tests t WHERE t.active=TRUE AND (t.access_type='open' OR EXISTS(
      SELECT 1 FROM assignments a WHERE a.test_id=t.id AND a.user_id=$1))
    ORDER BY t.created_at DESC`,[req.session.user.id]);
  res.json({tests:r.rows});
});
app.get('/api/tests/:id',requireAuth,async(req,res)=>{
  const r=await pool.query('SELECT * FROM tests WHERE id=$1 AND active=TRUE',[Number(req.params.id)]);
  if(!r.rowCount) return res.status(404).json({error:'Тест не найден'});
  const t=r.rows[0];
  if(t.access_type==='closed'){
    const a=await pool.query('SELECT id FROM assignments WHERE user_id=$1 AND test_id=$2',[req.session.user.id,t.id]);
    if(!a.rowCount && req.session.user.role!=='admin') return res.status(403).json({error:'Этот тест доступен только по назначению администратора'});
  }
  res.json({test:{id:t.id,title:t.title,category:t.category,description:t.description,duration_minutes:t.duration_minutes,pass_percent:t.pass_percent,
    questions:t.questions.map((q,i)=>({prompt:q.prompt,options:q.options}))}});
});
app.post('/api/tests/:id/submit',requireAuth,async(req,res)=>{
  const id=Number(req.params.id), r=await pool.query('SELECT * FROM tests WHERE id=$1 AND active=TRUE',[id]);
  if(!r.rowCount) return res.status(404).json({error:'Тест не найден'});
  const t=r.rows[0];
  if(t.access_type==='closed'){
    const a=await pool.query('SELECT id FROM assignments WHERE user_id=$1 AND test_id=$2',[req.session.user.id,id]);
    if(!a.rowCount && req.session.user.role!=='admin') return res.status(403).json({error:'Тест не назначен вам'});
  }
  const questions=t.questions, answers=req.body.answers;
  if(!Array.isArray(answers)||answers.length!==questions.length) return res.status(400).json({error:'Ответьте на все вопросы'});
  let score=0; questions.forEach((q,i)=>{if(Number(answers[i])===Number(q.correct)) score++;});
  const percent=Math.round(score/questions.length*100), passed=percent>=t.pass_percent;
  const saved=await pool.query(`INSERT INTO attempts(user_id,test_id,score,total,percent,passed,answers)
    VALUES($1,$2,$3,$4,$5,$6,$7::jsonb) RETURNING id,created_at`,
    [req.session.user.id,id,score,questions.length,percent,passed,JSON.stringify(answers)]);
  res.json({attemptId:saved.rows[0].id,createdAt:saved.rows[0].created_at,score,total:questions.length,percent,passed,passPercent:t.pass_percent});
});
app.get('/api/my/attempts',requireAuth,async(req,res)=>{
  const r=await pool.query(`SELECT a.id,a.score,a.total,a.percent,a.passed,a.created_at,t.title
    FROM attempts a JOIN tests t ON t.id=a.test_id WHERE a.user_id=$1 ORDER BY a.id DESC`,[req.session.user.id]);
  res.json({attempts:r.rows});
});
app.get('/api/certificate/:attemptId',requireAuth,async(req,res)=>{
  const r=await pool.query(`SELECT a.*,u.name,t.title FROM attempts a JOIN users u ON u.id=a.user_id
    JOIN tests t ON t.id=a.test_id WHERE a.id=$1`,[Number(req.params.attemptId)]);
  if(!r.rowCount) return res.status(404).json({error:'Результат не найден'});
  const a=r.rows[0];
  if(req.session.user.role!=='admin' && a.user_id!==req.session.user.id) return res.status(403).json({error:'Нет доступа'});
  if(!a.passed) return res.status(403).json({error:'Сертификат выдаётся после успешной сдачи'});
  res.json({certificate:{id:a.id,name:a.name,testTitle:a.title,score:a.score,total:a.total,percent:a.percent,date:a.created_at,center:process.env.CENTER_NAME||'ПрофРост-PV'}});
});

app.get('/api/admin/overview',requireAdmin,async(req,res)=>{
  const [users,tests,attempts]=await Promise.all([
    pool.query("SELECT id,name,email,role,created_at FROM users ORDER BY id DESC"),
    pool.query(`SELECT id,title,category,description,access_type,duration_minutes,pass_percent,
      jsonb_array_length(questions) AS question_count,active FROM tests ORDER BY id DESC`),
    pool.query(`SELECT a.id,a.score,a.total,a.percent,a.passed,a.created_at,u.name AS user_name,u.email,t.title AS test_title
      FROM attempts a JOIN users u ON u.id=a.user_id JOIN tests t ON t.id=a.test_id ORDER BY a.id DESC LIMIT 200`)
  ]);
  res.json({users:users.rows,tests:tests.rows,attempts:attempts.rows});
});
app.post('/api/admin/tests',requireAdmin,async(req,res)=>{
  const b=req.body, title=String(b.title||'').trim(), questions=b.questions;
  if(!title || !Array.isArray(questions)||!questions.length) return res.status(400).json({error:'Укажите название и минимум один вопрос'});
  for(const q of questions){
    if(!String(q.prompt||'').trim()||!Array.isArray(q.options)||q.options.length<2||q.options.some(x=>!String(x).trim())||
      !Number.isInteger(Number(q.correct))||Number(q.correct)<0||Number(q.correct)>=q.options.length)
      return res.status(400).json({error:'Проверьте вопросы: у каждого должны быть варианты и правильный ответ'});
  }
  const access=b.access_type==='closed'?'closed':'open';
  const duration=Math.max(1,Math.min(240,Number(b.duration_minutes)||20));
  const pass=Math.max(1,Math.min(100,Number(b.pass_percent)||70));
  const r=await pool.query(`INSERT INTO tests(title,category,description,access_type,duration_minutes,pass_percent,questions)
    VALUES($1,$2,$3,$4,$5,$6,$7::jsonb) RETURNING id`,
    [title,String(b.category||'Общие'),String(b.description||''),access,duration,pass,JSON.stringify(questions)]);
  res.json({id:r.rows[0].id});
});
app.put('/api/admin/tests/:id',requireAdmin,async(req,res)=>{
  const b=req.body;
  await pool.query(`UPDATE tests SET title=$1,category=$2,description=$3,access_type=$4,duration_minutes=$5,pass_percent=$6,questions=$7::jsonb,active=$8
    WHERE id=$9`,
    [String(b.title||'').trim(),String(b.category||'Общие'),String(b.description||''),b.access_type==='closed'?'closed':'open',
     Math.max(1,Math.min(240,Number(b.duration_minutes)||20)),Math.max(1,Math.min(100,Number(b.pass_percent)||70)),
     JSON.stringify(b.questions||[]),b.active!==false,Number(req.params.id)]);
  res.json({ok:true});
});
app.delete('/api/admin/tests/:id',requireAdmin,async(req,res)=>{
  await pool.query('DELETE FROM tests WHERE id=$1',[Number(req.params.id)]); res.json({ok:true});
});
app.post('/api/admin/assign',requireAdmin,async(req,res)=>{
  const email=String(req.body.email||'').trim().toLowerCase(), testId=Number(req.body.testId);
  const u=await pool.query("SELECT id FROM users WHERE email=$1 AND role='student'",[email]);
  if(!u.rowCount) return res.status(404).json({error:'Обучающийся с таким email не найден. Сначала он должен зарегистрироваться.'});
  const t=await pool.query("SELECT id FROM tests WHERE id=$1",[testId]);
  if(!t.rowCount) return res.status(404).json({error:'Тест не найден'});
  await pool.query('INSERT INTO assignments(user_id,test_id,assigned_by) VALUES($1,$2,$3) ON CONFLICT(user_id,test_id) DO NOTHING',
    [u.rows[0].id,testId,req.session.user.id]);
  res.json({ok:true});
});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
initDb().then(()=>app.listen(PORT,()=>console.log(`ПрофРост-PV запущен на порту ${PORT}`)))
  .catch(err=>{console.error('Ошибка запуска базы данных:',err);process.exit(1);});
