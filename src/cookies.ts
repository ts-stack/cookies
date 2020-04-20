/*!
 * cookies
 * Copyright(c) 2014 Jed Schmidt, http://jed.is/
 * Copyright(c) 2015-2016 Douglas Christopher Wilson
 * MIT Licensed
 */

import http = require('http');
import Keygrip = require('keygrip');

import { Cookie } from './cookie';
import { ObjectAny, CookieOptions, MinRequest, MinResponse } from './types';

const cache: ObjectAny = {};

export class Cookies {
  protected secure: boolean;
  protected keys: Keygrip;

  constructor(protected request: MinRequest, protected response: MinResponse, options: CookieOptions) {
    this.secure = undefined;

    if (options) {
      this.keys = Array.isArray((options as any).keys) ? new Keygrip((options as any).keys) : (options as any).keys;
      this.secure = options.secure;
    }
  }

  static connect(keys: Keygrip) {
    return this.express(keys);
  }

  static express(keys: Keygrip) {
    return function (req: MinRequest, res: MinResponse, next: () => void) {
      req.cookies = res.cookies = new Cookies(req, res, { keys } as any);

      next();
    };
  }

  get(name: string, opts?: CookieOptions) {
    const sigName = name + '.sig';
    const signed = opts && opts.signed !== undefined ? opts.signed : !!this.keys;

    const header = this.request.headers.cookie;
    if (!header) return;

    const match = header.match(this.getPattern(name));
    if (!match) return;

    const value = match[1];
    if (!opts || !signed) return value;

    const remote = this.get(sigName);
    if (!remote) return;

    const data = name + '=' + value;
    if (!this.keys) throw new Error('.keys required for signed cookies');
    const index = this.keys.index(data, remote);

    if (index < 0) {
      this.set(sigName, null, { path: '/', signed: false });
    } else {
      index && this.set(sigName, this.keys.sign(data), { signed: false });
      return value;
    }
  }

  set(name: string, value: any, opts?: CookieOptions) {
    const req = this.request;
    const res = this.response;
    const secure =
      this.secure !== undefined ? !!this.secure : req.protocol === 'https' || (req.connection as any).encrypted;
    const cookie = new Cookie(name, value, opts);
    const signed = opts && opts.signed !== undefined ? opts.signed : !!this.keys;

    let headers = (res.getHeader('Set-Cookie') || []) as string[];

    if (typeof headers == 'string') headers = [headers];

    if (!secure && opts && opts.secure) {
      throw new Error('Cannot send secure cookie over unencrypted connection');
    }

    cookie.secure = opts && opts.secure !== undefined ? opts.secure : secure;

    this.pushCookie(headers, cookie);

    if (opts && signed) {
      if (!this.keys) throw new Error('.keys required for signed cookies');
      cookie.value = this.keys.sign(cookie.toString());
      cookie.name += '.sig';
      this.pushCookie(headers, cookie);
    }

    const setHeader = res.set ? http.OutgoingMessage.prototype.setHeader : res.setHeader;
    setHeader.call(res, 'Set-Cookie', headers);
    return this;
  }

  protected getPattern(name: string) {
    if (cache[name]) return cache[name];

    return (cache[name] = new RegExp('(?:^|;) *' + name.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&') + '=([^;]*)'));
  }

  protected pushCookie(headers: string[], cookie: Cookie) {
    if (cookie.overwrite) {
      for (let i = headers.length - 1; i >= 0; i--) {
        if (headers[i].indexOf(cookie.name + '=') === 0) {
          headers.splice(i, 1);
        }
      }
    }

    headers.push(cookie.toHeader());
  }
}
