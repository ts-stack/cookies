import * as assert from 'node:assert';
import { Cookie } from './cookie.js';

describe('new Cookie(name, value, [options])', function () {
  it('should have correct constructor', function () {
    const cookie = new Cookie('foo', 'bar');
    assert.equal(cookie.constructor, Cookie);
  });

  it('should throw on invalid name', function () {
    assert.throws(function () {
      new Cookie('foo\n', 'bar');
    }, /argument name is invalid/);

    assert.throws(function () {
      assert.ok(!new Cookie('foo=', 'bar'));
    }, /argument name is invalid/);
  });

  it('should throw on invalid value', function () {
    assert.throws(function () {
      new Cookie('foo', 'bar\n');
    }, /argument value is invalid/);

    assert.throws(function () {
      assert.ok(!new Cookie('foo', 'bar;'));
    }, /argument value is invalid/);
  });

  it('should throw on invalid path', function () {
    assert.throws(function () {
      new Cookie('foo', 'bar', { path: '/\n' });
    }, /option path is invalid/);
  });

  it('should throw on invalid domain', function () {
    assert.throws(function () {
      new Cookie('foo', 'bar', { domain: 'example.com\n' });
    }, /option domain is invalid/);
  });

  describe('options', function () {
    describe('maxAge', function () {
      it('should set the .maxAge property', function () {
        const cookie = new Cookie('foo', 'bar', { maxAge: 86400 });
        assert.equal(cookie.maxAge, 86400);
      });

      it('should throw on invalid value', function () {
        assert.throws(function () {
          new Cookie('foo', 'bar', { maxAge: 'foo' as any });
        }, /option maxAge is invalid/);
      });

      it('should throw on Infinity', function () {
        assert.throws(function () {
          new Cookie('foo', 'bar', { maxAge: Infinity });
        }, /option maxAge is invalid/);
      });

      it('should throw on NaN', function () {
        assert.throws(function () {
          new Cookie('foo', 'bar', { maxAge: NaN });
        }, /option maxAge is invalid/);
      });
    });

    describe('partitioned', function () {
      it('should set the .partitioned property', function () {
        const cookie = new Cookie('foo', 'bar', { partitioned: true });
        assert.strictEqual(cookie.partitioned, true);
      });

      it('should default to false', function () {
        const cookie = new Cookie('foo', 'bar');
        assert.strictEqual(cookie.partitioned, false);
      });

      describe('when set to false', function () {
        it('should not set partitioned attribute in header', function () {
          const cookie = new Cookie('foo', 'bar', { partitioned: false });
          assert.strictEqual(cookie.toHeader(), 'foo=bar; path=/; httponly');
        });
      });

      describe('when set to true', function () {
        it('should set partitioned attribute in header', function () {
          const cookie = new Cookie('foo', 'bar', { partitioned: true });
          assert.strictEqual(cookie.toHeader(), 'foo=bar; path=/; httponly; partitioned');
        });
      });
    });

    describe('priority', function () {
      it('should set the .priority property', function () {
        const cookie = new Cookie('foo', 'bar', { priority: 'low' });
        assert.strictEqual(cookie.priority, 'low');
      });

      it('should default to undefined', function () {
        const cookie = new Cookie('foo', 'bar');
        assert.strictEqual(cookie.priority, undefined);
      });

      it('should throw on invalid value', function () {
        assert.throws(function () {
          new Cookie('foo', 'bar', { priority: 'foo' as any });
        }, /option priority is invalid/);
      });

      describe('when set to "low"', function () {
        it('should set "priority=low" attribute in header', function () {
          const cookie = new Cookie('foo', 'bar', { priority: 'low' });
          assert.strictEqual(cookie.toHeader(), 'foo=bar; path=/; priority=low; httponly');
        });
      });

      describe('when set to "medium"', function () {
        it('should set "priority=medium" attribute in header', function () {
          const cookie = new Cookie('foo', 'bar', { priority: 'medium' });
          assert.strictEqual(cookie.toHeader(), 'foo=bar; path=/; priority=medium; httponly');
        });
      });

      describe('when set to "high"', function () {
        it('should set "priority=high" attribute in header', function () {
          const cookie = new Cookie('foo', 'bar', { priority: 'high' });
          assert.strictEqual(cookie.toHeader(), 'foo=bar; path=/; priority=high; httponly');
        });
      });

      describe('when set to "HIGH"', function () {
        it('should set "priority=high" attribute in header', function () {
          const cookie = new Cookie('foo', 'bar', { priority: 'HIGH' as any });
          assert.strictEqual(cookie.toHeader(), 'foo=bar; path=/; priority=high; httponly');
        });
      });
    });

    describe('sameSite', function () {
      it('should set the .sameSite property', function () {
        const cookie = new Cookie('foo', 'bar', { sameSite: true });
        assert.equal(cookie.sameSite, true);
      });

      it('should default to false', function () {
        const cookie = new Cookie('foo', 'bar');
        assert.equal(cookie.sameSite, false);
      });

      it('should throw on invalid value', function () {
        assert.throws(function () {
          new Cookie('foo', 'bar', { sameSite: 'foo' as any });
        }, /option sameSite is invalid/);
      });

      describe('when set to "false"', function () {
        it('should not set "samesite" attribute in header', function () {
          const cookie = new Cookie('foo', 'bar', { sameSite: false });
          assert.equal(cookie.toHeader(), 'foo=bar; path=/; httponly');
        });
      });

      describe('when set to "true"', function () {
        it('should set "samesite=strict" attribute in header', function () {
          const cookie = new Cookie('foo', 'bar', { sameSite: true });
          assert.equal(cookie.toHeader(), 'foo=bar; path=/; samesite=strict; httponly');
        });
      });

      describe('when set to "lax"', function () {
        it('should set "samesite=lax" attribute in header', function () {
          const cookie = new Cookie('foo', 'bar', { sameSite: 'lax' as any });
          assert.equal(cookie.toHeader(), 'foo=bar; path=/; samesite=lax; httponly');
        });
      });

      describe('when set to "none"', function () {
        it('should set "samesite=none" attribute in header', function () {
          const cookie = new Cookie('foo', 'bar', { sameSite: 'none' as any });
          assert.equal(cookie.toHeader(), 'foo=bar; path=/; samesite=none; httponly');
        });
      });

      describe('when set to "strict"', function () {
        it('should set "samesite=strict" attribute in header', function () {
          const cookie = new Cookie('foo', 'bar', { sameSite: 'strict' as any });
          assert.equal(cookie.toHeader(), 'foo=bar; path=/; samesite=strict; httponly');
        });
      });

      describe('when set to "STRICT"', function () {
        it('should set "samesite=strict" attribute in header', function () {
          const cookie = new Cookie('foo', 'bar', { sameSite: 'STRICT' as any });
          assert.equal(cookie.toHeader(), 'foo=bar; path=/; samesite=strict; httponly');
        });
      });
    });
  });
});
