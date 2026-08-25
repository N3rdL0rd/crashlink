class Widget {
	public var id:Int;
	public function new(id:Int) {
		this.id = id;
		Sys.println("Widget constructed: " + id);
	}
}

class Factory {
	public static var w1:Widget = new Widget(1);
	public static var w2:Widget = new Widget(2);
}

class StaticInitConstructsOther {
	static function main() {
		Sys.println("main start");
		trace(Factory.w1.id);
		trace(Factory.w2.id);
	}
}
