import * as assert from 'node:assert';
import defaultKeys from 'keygrip';
import request from 'supertest';
import express from 'express';

import { Cookies } from '#lib/cookies.js';

const keys = defaultKeys(['a', 'b']);

function cookies(keys?: defaultKeys | string[]) {
  return function (req: any, res: any, next: any) {
    req.cookies = res.cookies = new Cookies(req, res, { keys });

    next();
  };
}

describe('Express', function () {
  it('should set a cookie on the response', function (done) {
    const app = express();

    app.set('env', 'test');
    app.use(cookies());
    app.get('/', function (req: any, res: any) {
      res.cookies.set('foo', 'bar');
      res.end();
    });

    request(app)
      .get('/')
      .expect(shouldSetCookies([{ name: 'foo', value: 'bar', path: '/', httponly: true }]))
      .expect(200, done);
  });

  it('should get a cookie from the request', function (done) {
    const app = express();

    app.set('env', 'test');
    app.use(cookies());
    app.get('/', function (req: any, res: any) {
      res.json({ foo: String(res.cookies.get('foo')) });
    });

    request(app).get('/').set('cookie', 'foo=bar').expect(200, { foo: 'bar' }, done);
  });

  describe('with multiple cookies', function () {
    it('should set all cookies on the response', function (done) {
      const app = express();

      app.set('env', 'test');
      app.use(cookies());
      app.get('/', function (req: any, res: any) {
        res.cookies.set('foo', 'bar');
        res.cookies.set('fizz', 'buzz');
        res.end();
      });

      request(app)
        .get('/')
        .expect(
          shouldSetCookies([
            { name: 'foo', value: 'bar', path: '/', httponly: true },
            { name: 'fizz', value: 'buzz', path: '/', httponly: true },
          ]),
        )
        .expect(200, done);
    });

    it('should get each cookie from the request', function (done) {
      const app = express();

      app.set('env', 'test');
      app.use(cookies());
      app.get('/', function (req: any, res: any) {
        res.json({
          fizz: String(res.cookies.get('fizz')),
          foo: String(res.cookies.get('foo')),
        });
      });

      request(app).get('/').set('cookie', 'foo=bar; fizz=buzz').expect(200, { foo: 'bar', fizz: 'buzz' }, done);
    });
  });

  describe('when "overwrite: false"', function () {
    it('should set second cookie with same name', function (done) {
      const app = express();

      app.set('env', 'test');
      app.use(cookies());
      app.get('/', function (req: any, res: any) {
        res.cookies.set('foo', 'bar');
        res.cookies.set('foo', 'fizz', { overwrite: false });
        res.end();
      });

      request(app)
        .get('/')
        .expect(
          shouldSetCookies([
            { name: 'foo', value: 'bar', path: '/', httponly: true },
            { name: 'foo', value: 'fizz', path: '/', httponly: true },
          ]),
        )
        .expect(200, done);
    });
  });

  describe('when "overwrite: true"', function () {
    it('should replace previously set value', function (done) {
      const app = express();

      app.set('env', 'test');
      app.use(cookies());
      app.get('/', function (req: any, res: any, next: any) {
        res.cookies.set('foo', 'bar');
        res.cookies.set('foo', 'fizz', { overwrite: true });
        res.end();
      });

      request(app)
        .get('/')
        .expect(shouldSetCookies([{ name: 'foo', value: 'fizz', path: '/', httponly: true }]))
        .expect(200, done);
    });

    it('should set signature correctly', function (done) {
      const app = express();

      app.set('env', 'test');
      app.use(cookies(keys));
      app.get('/', function (req: any, res: any, next: any) {
        res.cookies.set('foo', 'bar');
        res.cookies.set('foo', 'fizz', { overwrite: true });
        res.end();
      });

      request(app)
        .get('/')
        .expect(
          shouldSetCookies([
            { name: 'foo', value: 'fizz', path: '/', httponly: true },
            { name: 'foo.sig', value: 'hVIYdxZSelh3gIK5wQxzrqoIndU', path: '/', httponly: true },
          ]),
        )
        .expect(200, done);
    });
  });

  describe('when "secure: true"', function () {
    it('should set for secure connection', function (done) {
      const app = express();

      app.set('env', 'test');
      app.use(cookies(keys));
      app.use(function (req: any, res: any, next: any) {
        res.connection.encrypted = true;
        next();
      });
      app.use(function (req: any, res: any) {
        res.cookies.set('foo', 'bar', { secure: true });
        res.end();
      });

      request(app)
        .get('/')
        .expect(
          shouldSetCookies([
            { name: 'foo', value: 'bar', path: '/', httponly: true, secure: true },
            { name: 'foo.sig', value: 'p5QVCZeqNBulWOhYipO0jqjrzz4', path: '/', httponly: true, secure: true },
          ]),
        )
        .expect(200, done);
    });

    it('should set for proxy settings', function (done) {
      const app = express();

      app.set('env', 'test');
      app.set('trust proxy', true);
      app.use(cookies(keys));
      app.use(function (req: any, res: any) {
        res.cookies.set('foo', 'bar', { secure: true });
        res.end();
      });

      request(app)
        .get('/')
        .set('X-Forwarded-Proto', 'https')
        .expect(
          shouldSetCookies([
            { name: 'foo', value: 'bar', path: '/', httponly: true, secure: true },
            { name: 'foo.sig', value: 'p5QVCZeqNBulWOhYipO0jqjrzz4', path: '/', httponly: true, secure: true },
          ]),
        )
        .expect(200, done);
    });
  });
});

function getCookies(res: any) {
  const setCookies = res.headers['set-cookie'] || [];
  return setCookies.map(parseSetCookie);
}

function parseSetCookie(header: string) {
  let match;
  const pairs = [];
  const pattern = /\s*([^=;]+)(?:=([^;]*);?|;|$)/g;

  while ((match = pattern.exec(header))) {
    pairs.push({ name: match[1], value: match[2] });
  }

  const cookie = pairs.shift();

  for (let i = 0; i < pairs.length; i++) {
    match = pairs[i];
    (cookie as any)[match.name.toLowerCase()] = match.value || true;
  }

  return cookie;
}

function shouldSetCookies(expected: any) {
  return function (res: any) {
    assert.deepEqual(getCookies(res), expected);
  };
}
