import type Keygrip from 'keygrip';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Http2ServerRequest, Http2ServerResponse } from 'node:http2';

export type NodeRequest = IncomingMessage | Http2ServerRequest;
export type NodeResponse = ServerResponse | Http2ServerResponse;

export interface ObjectAny {
  [key: string]: any;
}

export class CookieOptions {
  /**
   * A number representing the milliseconds from `Date.now()` for expiry.
   */
  maxAge?: number;
  /**
   * A `Date` object indicating the cookie's expiration date (expires at the end of session by default).
   */
  expires?: Date;
  /**
   * A string indicating the path of the cookie (`/` by default).
   */
  path?: string;
  /**
   * A string indicating the domain of the cookie (no default).
   */
  domain?: string;
  /**
   * A boolean indicating whether the cookie is only to be sent over HTTPS
   * (`false` by default for HTTP, `true` by default for HTTPS).
   */
  secure?: boolean;
  /**
   * A boolean indicating whether the cookie is only to be sent over HTTP(S),
   * and not made available to client JavaScript (`true` by default).
   */
  httpOnly?: boolean;
  /**
   * A boolean or string indicating whether the cookie is a "same site" cookie (`false` by default).
   * This can be set to `'strict'`, `'lax'`, `'none'`, or `true` (which maps to `'strict'`).
   */
  sameSite?: 'strict' | 'lax' | 'none' | boolean | undefined;
  /**
   * A boolean indicating whether the cookie is to be signed (`false` by default).
   * If this is true, another cookie of the same name with the `.sig` suffix appended will also be sent,
   * with a 27-byte url-safe base64 SHA1 value representing the hash of `cookie-name=cookie-value` against
   * the first Keygrip key. This signature key is used to detect tampering the next time a cookie is received.
   */
  signed?: boolean;
  /**
   * A boolean indicating whether to overwrite previously set cookies of the same name (`false` by default).
   * If this is true, all cookies set during the same request with the same name (regardless of path or domain)
   * are filtered out of the Set-Cookie header when setting this cookie.
   */
  overwrite?: boolean;
  /**
   * This option allowing inbound cookies to be read using `cookies.get` and outbound cookies to be set using `cookies.set`.
   */
  keys?: Keygrip | string[];
  /**
   * a boolean indicating whether to partition the cookie in Chrome for the [CHIPS Update][1] (`false` by default).
   * If this is true, Cookies from embedded sites will be partitioned and only readable from the same top
   * level site from which it was created.
   *
   * [1]: https://developers.google.com/privacy-sandbox/3pcd/chips
   */
  partitioned?: boolean;
  /**
   * a string indicating the cookie priority. This can be set to `low`, `medium`, or `high`.
   */
  priority?: 'low' | 'medium' | 'high';
}
