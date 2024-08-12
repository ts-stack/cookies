/**
 * RegExp to match field-content in RFC 7230 sec 3.2
 *
 * field-content = field-vchar [ 1*( SP / HTAB ) field-vchar ]
 * field-vchar   = VCHAR / obs-text
 * obs-text      = %x80-FF
 */

import { CookieOptions } from './types.js';

// eslint-disable-next-line no-control-regex
const fieldContentRegExp = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;

/**
 * RegExp to match Same-Site cookie attribute value.
 */
const SAME_SITE_REGEXP = /^(?:lax|none|strict)$/i;

/**
 * RegExp to match basic restricted name characters for loose validation.
 */
const RESTRICTED_NAME_CHARS_REGEXP = /[;=]/;

/**
 * RegExp to match basic restricted value characters for loose validation.
 */
const RESTRICTED_VALUE_CHARS_REGEXP = /[;]/;

/**
 * RegExp to match Priority cookie attribute value.
 */
const PRIORITY_REGEXP = /^(?:low|medium|high)$/i;

export class Cookie {
  path?: string = '/';
  expires?: Date = undefined;
  domain?: string = undefined;
  httpOnly?: boolean = true;
  sameSite?: boolean = false;
  secure?: boolean = false;
  overwrite?: boolean = false;
  maxAge?: number | null;
  partitioned?: boolean = false;
  priority?: string;

  constructor(
    public name: string,
    public value?: any,
    attrs?: CookieOptions,
  ) {
    if (!fieldContentRegExp.test(name) || RESTRICTED_NAME_CHARS_REGEXP.test(name)) {
      throw new TypeError('argument name is invalid');
    }

    if (value && (!fieldContentRegExp.test(value) || RESTRICTED_VALUE_CHARS_REGEXP.test(value))) {
      throw new TypeError('argument value is invalid');
    }

    this.value = value || '';
    this.copyOpts(attrs);

    if (!this.value) {
      this.expires = new Date(0);
      this.maxAge = null;
    }

    if (this.path && !fieldContentRegExp.test(this.path)) {
      throw new TypeError('option path is invalid');
    }

    if (this.domain && !fieldContentRegExp.test(this.domain)) {
      throw new TypeError('option domain is invalid');
    }

    if (typeof this.maxAge === 'number' ? isNaN(this.maxAge) || !isFinite(this.maxAge) : this.maxAge) {
      throw new TypeError('option maxAge is invalid');
    }

    if (this.priority && !PRIORITY_REGEXP.test(this.priority)) {
      throw new TypeError('option priority is invalid');
    }

    if (this.sameSite && this.sameSite !== true && !SAME_SITE_REGEXP.test(this.sameSite)) {
      throw new TypeError('option sameSite is invalid');
    }
  }

  protected copyOpts(attrs: CookieOptions = {}) {
    Object.entries(attrs).forEach(([key, val]) => {
      if (val !== undefined) {
        (this as any)[key] = val;
      }
    });
  }

  toString() {
    return `${this.name}=${this.value}`;
  }

  toHeader() {
    let header = this.toString();

    if (this.maxAge) this.expires = new Date(Date.now() + this.maxAge);

    if (this.path) header += '; path=' + this.path;
    if (this.expires) header += '; expires=' + this.expires.toUTCString();
    if (this.domain) header += '; domain=' + this.domain;
    if (this.priority) header += '; priority=' + this.priority.toLowerCase();
    if (this.sameSite) {
      header += '; samesite=' + (this.sameSite === true ? 'strict' : (this.sameSite as string).toLowerCase());
    }
    if (this.secure) header += '; secure';
    if (this.httpOnly) header += '; httponly';
    if (this.partitioned) header += '; partitioned';

    return header;
  }
}
