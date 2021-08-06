const Router = require("koa-router");
const { authenticate } = require("ldap-authentication");
const config = require("../config.json");
const crypto = require("crypto");
const domain = config.domain.split(".");
const util = require("./util");

const router = new Router();

router.get("/", async (ctx, next) => {
    if(ctx.session.auth && util.has(ctx.session.auth)) {
        return ctx.redirect("/admin.html");
    }
    await next();
});

router.post("/auth", async ctx => {
    const body = ctx.request.body;
    if(!body || !body.password || !body.user) {
        return ctx.redirect("/?error=Login incorrecto");
    }
    let auth = await authenticate({
        ldapOpts: {
            url: config.servers
        },
        adminDn: `cn=${config.admin.user},ou=.ar,ou=Users,ou=Adistec,dc=${domain[0]},dc=${domain[1]}`,
        adminPassword: config.admin.password,
        userSearchBase: `dc=${domain[0]},dc=${domain[1]}`,
        userPassword: body.password,
        usernameAttribute: "sAMAccountName",
        username: body.user
    }).catch(e => {
        console.error(e);
        return false;
    });
    if(!auth || !config.ITUsers.includes(auth.sAMAccountName.toLowerCase())) {
        return ctx.redirect("/?error=Login incorrecto");
    }
    const key = generateKey();
    util.set(key, auth.sAMAccountName);
    ctx.session.auth = key;
    console.log(`${auth.sAMAccountName} se logueo`);
    return ctx.redirect("/admin.html");
});

function generateKey() {
    const key = crypto.randomBytes(32).toString("base64");
    if(util.has(key)) return generateKey();
    return key;
}

module.exports = router;