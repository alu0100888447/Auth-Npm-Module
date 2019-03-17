const fs = require('fs');
const bcrypt = require('bcrypt-nodejs');
const salt = bcrypt.genSaltSync(10);
const express = require('express');
const router = express.Router();

module.exports = function(options) {
  const {
    passwordFile, 
    pathToProtect,
    loginView,
    fullLoginView,
    logoutView,
    errorLoginView,
    registerFormView,
    errorRegisterView,
    registeredView
  } = options;
  if (!fs.existsSync(passwordFile)) fs.writeFileSync(passwordFile, '{}');

  // Funcion de autenticación, si existe nombre y password en la sesión, se puede ver el contenido
  const auth = function(req, res, next) {
      if(req.session && req.session.username && req.session.password){
        return next();
      }
      else { // https://developer.mozilla.org/es/docs/Web/HTTP/Status/401 
        return res.sendStatus(401); // 401: falta autenticación para el recurso solicitado.
      }
    };

  //Ruta estática para ver el contenido, se necesita haber iniciado previamente sesion
  router.use('/content', 
    auth, // our middleware!
    express.static(pathToProtect)
  );

  //Fase de login ////////////////////////////////////////////////////////////////
  router.get('/login', function (req, res) {
    if ( (!req.session.username)) {
      res.render(loginView);
    }
    else if ((req.session.username)) {
      res.render(fullLoginView, {username:req.session.username});
    }
  });

  router.post('/login', function(req,res){
    let configFile = fs.readFileSync(passwordFile);
    let config = JSON.parse(configFile);

    let p = config[req.body.username];
    if (p) {
      if ((req.session) && req.body && req.body.password && (bcrypt.compareSync(req.body.password, p))){
        req.session.username = req.body.username;
        req.session.password = req.body.password;
        req.session.admin = true;
        return res.render(fullLoginView, {username:req.session.username});
      } 
      else
       return res.render(errorLoginView);
    }
    else
     return res.render(errorLoginView);
  });

  //Fase de registro /////////////////////////////////////////////////////////////
  router.get('/register', function (req, res) {
    if ((!req.session.username)) {
      res.render(registerFormView);
    }
    else{
      res.render(fullLoginView, {username:req.session.username});
    }
  });

  router.post('/register', function (req, res) {
    let configFile = fs.readFileSync(passwordFile);
    let config = JSON.parse(configFile);
    let p = config[req.body.username];

    if (!p) config[req.body.username] = bcrypt.hashSync(req.body.password, salt);
    else return res.render(errorRegisterView, req.body.username);

    let configJSON = JSON.stringify(config);
    fs.writeFileSync(passwordFile, configJSON);
    res.render(registeredView, {username:req.body.username});

  });

  //Cerrar sesion ////////////////////////////////////////////////////////////////
  router.get('/logout', function(req,res){
    let user = req.session.username;
    req.session.destroy();
    res.render(logoutView, { user});

  });
  return router;
};

