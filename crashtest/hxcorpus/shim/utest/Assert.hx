package utest;

/** Minimal deterministic stand-in for utest.Assert: prints one line per assertion, no positions. */
class Assert {
	static function show(v:Dynamic):String {
		return Std.string(v);
	}

	static function report(ok:Bool, what:String, ?msg:String):Bool {
		Sys.println((ok ? "ok " : "FAIL ") + what + (ok || msg == null ? "" : " " + msg));
		return ok;
	}

	public static function pass(?msg:String, ?pos:haxe.PosInfos):Bool return report(true, "pass");

	public static function fail(?msg:String, ?pos:haxe.PosInfos):Bool return report(false, "fail", msg);

	public static function isTrue(v:Bool, ?msg:Dynamic, ?pos:haxe.PosInfos):Bool return report(v == true, "isTrue");

	public static function isFalse(v:Bool, ?msg:Dynamic, ?pos:haxe.PosInfos):Bool return report(v == false, "isFalse");

	public static function isNull(v:Dynamic, ?msg:Dynamic, ?pos:haxe.PosInfos):Bool return report(v == null, "isNull");

	public static function notNull(v:Dynamic, ?msg:Dynamic, ?pos:haxe.PosInfos):Bool return report(v != null, "notNull");

	public static function equals(expected:Dynamic, actual:Dynamic, ?msg:Dynamic, ?pos:haxe.PosInfos):Bool
		return report(expected == actual, "equals", show(expected) + " vs " + show(actual));

	public static function notEquals(expected:Dynamic, actual:Dynamic, ?msg:Dynamic, ?pos:haxe.PosInfos):Bool
		return report(expected != actual, "notEquals", show(expected));

	public static function floatEquals(expected:Float, actual:Float, ?approx:Float, ?msg:Dynamic, ?pos:haxe.PosInfos):Bool {
		var close = (Math.isNaN(expected) && Math.isNaN(actual)) || expected == actual || Math.abs(expected - actual) < 1e-5;
		return report(close, "floatEquals", show(expected) + " vs " + show(actual));
	}

	public static function same(expected:Dynamic, actual:Dynamic, ?recursive:Bool, ?msg:Dynamic, ?pos:haxe.PosInfos):Bool
		return report(show(expected) == show(actual), "same", show(expected) + " vs " + show(actual));

	public static function contains<T>(match:T, values:Array<T>, ?msg:Dynamic, ?pos:haxe.PosInfos):Bool
		return report(values.indexOf(match) >= 0, "contains", show(match));

	public static function raises(f:() -> Void, ?type:Dynamic, ?msg:Dynamic, ?pos:haxe.PosInfos):Bool {
		var threw = false;
		try {
			f();
		} catch (e:Dynamic) {
			threw = true;
		}
		return report(threw, "raises");
	}
}
