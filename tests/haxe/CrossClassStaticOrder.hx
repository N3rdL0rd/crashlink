class Logger {
	public static var log:Array<String> = [];
	public static function add(s:String):Void {
		log.push(s);
	}
}

class A {
	public static var tag:String = init();
	static function init():String {
		Logger.add("A.init");
		return "A";
	}
}

class B {
	public static var x:Int = doInit();
	static function doInit():Int {
		Logger.add("B.init sees A.tag=" + A.tag);
		return 42;
	}
}

class CrossClassStaticOrder {
	static function main() {
		Logger.add("main start");
		trace(B.x);
		trace(A.tag);
		for (s in Logger.log) trace(s);
	}
}
