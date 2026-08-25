class Singleton {
	public static var instance:Singleton = new Singleton();
	public var value:Int;
	public function new() {
		value = 7;
		Sys.println("Singleton constructed");
	}
	public function bump():Int {
		value++;
		return value;
	}
}

class SingletonStaticInit {
	static function main() {
		trace(Singleton.instance.value);
		trace(Singleton.instance.bump());
		trace(Singleton.instance.bump());
	}
}
