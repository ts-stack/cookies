/*!
 * cookies
 * Copyright(c) 2014 Jed Schmidt, http://jed.is/
 * Copyright(c) 2015-2016 Douglas Christopher Wilson
 * MIT Licensed
 */

import Keygrip from 'keygrip';

import { Cookie } from './cookie.js';
import { CookieOptions, NodeRequest, NodeResponse } from './types.js';

/**
 * Cache for generated name regular expressions.
 */
const REGEXP_CACHE = Object.create(null);

/**
 * RegExp to match all characters to escape in a RegExp.
 */
const REGEXP_ESCAPE_CHARS_REGEXP = /[\^$\\.*+?()[\]{}|]/g;

export class Cookies {
  secure?: boolean;
  keys?: Keygrip;

  constructor(
    protected request: NodeRequest,
    protected response: NodeResponse,
    options?: CookieOptions,
  ) {
    this.secure = undefined;

    if (options) {
      this.keys = Array.isArray(options.keys) ? new Keygrip(options.keys) : options.keys;
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

    let value = match[1];
    if (value[0] === '"') value = value.slice(1, -1);
    if (!opts || !signed) return value;

    const remote = this.get(sigName);
    if (!remote) return;

    const data = name + '=' + value;
    if (!this.keys) throw new Error('.keys required for signed cookies');
    const index = this.keys.index(data, remote);

    if (index < 0) {
      this.set(sigName, null, { path: '/', signed: false });
      return;
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
    const res = this.response;
    const cookie = new Cookie(name, value, opts);
    const signed = opts?.signed !== undefined ? opts.signed : !!this.keys;
    cookie.secure = this.secure === undefined ? this.isRequestEncrypted(this.request) : Boolean(this.secure);

    const rawHeaders = res.getHeader('Set-Cookie') || [];
    const headers = typeof rawHeaders == 'string' ? [rawHeaders] : (rawHeaders as string[]);

    this.pushCookie(headers, cookie);

    if (opts && signed) {
      if (!this.keys) throw new Error('.keys required for signed cookies');
      cookie.value = this.keys.sign(cookie.toString());
      cookie.name += '.sig';
      this.pushCookie(headers, cookie);
    }

    res.setHeader('Set-Cookie', headers);
    return this;
  }

  /**
   * Get the pattern to search for a cookie in a string.
   */
  protected getPattern(name: string) {
    if (!REGEXP_CACHE[name]) {
      REGEXP_CACHE[name] = new RegExp('(?:^|;) *' + name.replace(REGEXP_ESCAPE_CHARS_REGEXP, '\\$&') + '=([^;]*)');
    }

    return REGEXP_CACHE[name];
  }

  /**
   * Get the encrypted status for a request.
   */
  protected isRequestEncrypted(req: any) {
    return req.socket?.encrypted || req.connection?.encrypted;
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
