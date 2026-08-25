class Builder {
	public var log:String = "";
	public function new() {}
	public function add(s:String):Builder {
		log += s;
		return this;
	}
	public function reset():Builder {
		log = "";
		return this;
	}
}

class FluentChain {
	static function main() {
		var b = new Builder();
		var r = b.add("a").add("b").reset().add("c");
		trace(r.log);
		trace(r == b);
		var b2 = new Builder().add("x").add("y");
		trace(b2.log);
	}
}
