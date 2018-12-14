const _ = require("lodash"),
	jwt = require("jsonwebtoken"),
	utils = require("./utils");


const sessionSerialize = function (session) {
	return _.reduce(session, function(memo, val, key){
		if(typeof val !== "function" && key !== "id")
			memo[key] = val;
		return memo;
	}, {});
};

const sessionDeserialize = function (o) {
	return new Promise(function (resolve, reject) {
		resolve(session);
	});
};

module.exports = function(options){

	if(!options.client || !options.secret)
		throw new Error("Redis client and secret required for JWT Redis Session!");

	options = {
		client: options.client,
		secret: options.secret,
		algorithm: options.algorithm || "HS256",
		keyspace: options.keyspace || "sess:",
		maxAge: options.maxAge || 86400,
		requestKey: options.requestKey || "session",
		requestArg: options.requestArg || "accessToken",
		sessionSerialize: options.sessionSerialize || sessionSerialize,
		sessionDeserialize: options.sessionDeserialize || sessionDeserialize
	};

	var SessionUtils = utils(options);
	
	return function jwtRedisSession(req, res, next){

		req[options.requestKey] = new SessionUtils();

		var token;

		req.rawHeaders.forEach(function(elem, i, headers){
			if (elem === 'Authorization') {
				token = headers[i + 1];
			}
		});

		if(!token && req._query) {
			token = req._query[options.requestArg];
		}

		if(token){
			jwt.verify(token, options.secret, function(error, decoded){
				if(error || !decoded.jti)
					return next();

				options.client.get(options.keyspace + decoded.jti, function(err, session){
					if(err || !session)
						return next(); 

					try{
						options.sessionDeserialize(JSON.parse(session)).then(function(session) {
							_.extend(req[options.requestKey], session);
							req[options.requestKey].claims = decoded;
							req[options.requestKey].id = decoded.jti;
							req[options.requestKey].jwt = token;
							// Update the TTL
							req[options.requestKey].touch(_.noop);
							next();
						}, function () { next(); });
					}catch(e){
						return next();
					}
				});
			});
		}else{
			next(); 
		}
	};

};
