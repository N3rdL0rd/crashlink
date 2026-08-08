class Emitter {
	public static var _unused = mark();
	static function mark():Int {
		Sys.println("static-init: Emitter loaded");
		return 1;
	}
}

class StaticInitSideEffectOrder {
	static var _touch = Emitter._unused;
	static function main() {
		Sys.println("main start");
		Sys.println("main end");
	}
}
