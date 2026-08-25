class Helper {
	public static var base = 10;
	public static var mul = makeMul();
	static function makeMul() {
		var captured = base;
		return function(x: Int) return x * captured + Other.offset;
	}
}

class Other {
	public static var offset = 5;
}

class StaticInitClosureOrder {
	static function main() {
		trace(Helper.mul(3));
		Helper.base = 100;
		trace(Helper.mul(3));
		Other.offset = 1000;
		trace(Helper.mul(3));
	}
}
