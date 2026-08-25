class FuncRefEquality {
	public function new() {}
	public function method():Int {
		return 42;
	}
	static function staticMethod():Int {
		return 1;
	}
	static function main() {
		var o = new FuncRefEquality();
		var f1 = o.method;
		var f2 = o.method;
		trace(f1 == f2);
		var s1 = staticMethod;
		var s2 = staticMethod;
		trace(s1 == s2);
		var o2 = new FuncRefEquality();
		var f3 = o2.method;
		trace(f1 == f3);
	}
}
