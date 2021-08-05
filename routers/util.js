const { cookie } = require("../config.json");
const session = new Map();

setInterval(() => {
    for(const [key, info] of session) {
        if(info.expire > Date.now()) continue;
        session.delete(key);
        console.log(`deleted ${key}`);
    }
}, cookie.duration);

module.exports = class Util {
    static set(key, user) {
        session.set(key, {
            expire: Date.now() + cookie.duration,
            user
        });
    }
    
    static get(key) {
        return session.get(key);
    }

    static has(key) {
        return session.has(key);
    }
};