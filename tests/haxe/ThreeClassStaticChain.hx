class C3 {
	public static var val:Int = 3;
}

class B3 {
	public static var val:Int = C3.val * 10;
}

class A3 {
	public static var val:Int = B3.val + C3.val;
}

class ThreeClassStaticChain {
	static function main() {
		trace(A3.val);
		trace(B3.val);
		trace(C3.val);
	}
}
