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

  /**
   * This extracts the cookie with the given name from the Cookie header in the request.
   * If such a cookie exists, its value is returned. Otherwise, nothing is returned.
   *
   * `{ signed: true }` can optionally be passed as the second parameter options.
   * In this case, a signature cookie (a cookie of same name ending with the `.sig` suffix appended) is fetched.
   * If no such cookie exists, nothing is returned.
   *
   * If the signature cookie does exist, the provided Keygrip object is used to check
   * whether the hash of `cookie-name=cookie-value` matches that of any registered key:
   * - If the signature cookie hash matches the first key, the original cookie value is returned.
   * - If the signature cookie hash matches any other key, the original cookie value is returned
   * AND an outbound header is set to update the signature cookie's value to the hash of the first key.
   * This enables automatic freshening of signature cookies that have become stale due to key rotation.
   * - If the signature cookie hash does not match any key, nothing is returned,
   * and an outbound header with an expired date is used to delete the cookie.
   */
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
      if (index) {
        this.set(sigName, this.keys.sign(data), { signed: false });
      }
      return value;
    }
  }

  /**
   * This sets the given cookie in the response and returns the current context to allow chaining.
   *
   * @param value If the value is omitted, an outbound header with an expired date is used to delete the cookie.
   * @param opts If the options object is provided,
   * it will be used to generate the outbound cookie header with `CookieOptions` type.
   */
  set(name: string, value?: any, opts?: CookieOptions) {
    const req = this.request;
    const res = this.response;
    const secure =
      this.secure !== undefined ? !!this.secure : req.protocol === 'https' || (req.connection as any).encrypted;
    const cookie = new Cookie(name, value, opts);
    const signed = opts && opts.signed !== undefined ? opts.signed : !!this.keys;

    const rawHeaders = res.getHeader('Set-Cookie') || [];
    const headers = typeof rawHeaders == 'string' ? [rawHeaders] : (rawHeaders as string[]);

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
