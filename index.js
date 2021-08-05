const Koa = require("koa");
const bodyparser = require("koa-bodyparser");
const session = require("koa-session");
const statics = require("koa-static");
const auth = require("./routers/auth");
const admin = require("./routers/admin");
const { cookie } = require("./config.json");
const SESSION_CONFIG = {
    maxAge: cookie.duration
};

const app = new Koa();
app.keys = cookie.keys;

app.use(bodyparser());
app.use(session(SESSION_CONFIG, app));
app.use(statics("./www/", {
    defer: true
}));
app.use(auth.routes());
app.use(admin.routes());

app.listen(9999);
console.log("Server is online");
