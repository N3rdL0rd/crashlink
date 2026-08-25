class SOMBase {
	public var tag:String = "base";

	public function new() {}

	public function greet():String {
		return "base-hello";
	}

	public function combo():String {
		return "[" + greet() + "]";
	}
}

class SOMChild extends SOMBase {
	public override function greet():String {
		var mid = super.greet();
		return mid + "-child";
	}
}

class SuperOverrideMidBody {
	static function main() {
		var c = new SOMChild();
		trace(c.greet());
		trace(c.combo());
		var b:SOMBase = c;
		trace(b.greet());
	}
}
