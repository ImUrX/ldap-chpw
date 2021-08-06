const Router = require("koa-router");
const util = require("./util");
const { promisify } = require("util");
const ldap = require("ldapjs");
const { once } = require("events");

const config = require("../config.json");
const domain = config.domain.split(".");

const router = new Router();

router.get("/admin.html", async (ctx, next) => {
    if(!ctx.session.auth || !util.has(ctx.session.auth)) {
        return ctx.redirect("/");
    }
    await next();
});

router.post("/change", async ctx => {
    if(!ctx.session.auth || !util.has(ctx.session.auth)) {
        return ctx.redirect("/");
    }
    const body = ctx.request.body;
    if(!body || !body.password || !body.user) {
        return ctx.redirect("/admin.html?error=Formato invalido");
    }
    if(config.blacklist.includes(body.user.toLowerCase())) {
        console.log(`${util.get(ctx.session.auth).user} le trato de cambiar la contraseña a ${body.user} (blacklist)`);
        return ctx.redirect("/admin.html?error=Trataste de cambiar la contraseña de alguien que no puede tenerla cambiada.");
    }

    const client = ldap.createClient({
        url: config.servers
    });
    await promisify(client.bind).call(client, `cn=${config.admin.user},ou=.ar,ou=Users,ou=Adistec,dc=${domain[0]},dc=${domain[1]}`, config.admin.password);
    const results = [];
    client.on("error", err => console.error(err.message));

    client.search(`dc=${domain[0]},dc=${domain[1]}`, {
        filter: `(sAMAccountName=${escapeDangerousChars(body.user)})`,
        attributes: "sAMAccountName",
        scope: "sub"
    }, (err, res) => {
        if(err) console.error(err);

        res.on("searchEntry", (entry) => {
            results.push(entry.object);
        });
        res.on("error", (err) => {
            console.error("error: " + err.message);
        });
        res.on("end", () => {
            client.emit("finishedQuery");
        });
    });

    await once(client, "finishedQuery");
    if(results.length === 0) {
        return ctx.redirect("/admin.html?error=El usuario no pude ser encontrado");
    }
    client.modify(results[0].dn, [
        new ldap.Change({
            operation: "replace",
            modification: {
                unicodePwd: encodePassword(body.password)
            }
        })
    ], err => {
        client.emit("finishedModify", err);
    });
    const err = await once(client, "finishedModify");
    client.destroy();
    if(err[0]) {
        console.log(`${util.get(ctx.session.auth).user} le trato de cambiar la contraseña a ${body.user}`);
        console.error(JSON.stringify(err));
        ctx.redirect(`/admin.html?error=${encodeURIComponent(JSON.stringify(err))}`);
    } else {
        console.log(`${util.get(ctx.session.auth).user} le cambio la contraseña a ${body.user}`);
        ctx.redirect("/admin.html?info=La contraseña se ha cambiado");
    }
});

function escapeDangerousChars(rfc2254) {
    return rfc2254.replaceAll(/\*|\0|\(|\)|\\/g, match => `\\${match.charCodeAt()}`);
}

function encodePassword(password) {
    return Buffer.from(`"${password}"`, "utf16le").toString();
}

module.exports = router;