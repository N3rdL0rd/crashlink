class SameClassDeclOrder {
	public static var a:Int = b + 1;
	public static var b:Int = 5;

	static function main() {
		trace(a);
		trace(b);
	}
}
