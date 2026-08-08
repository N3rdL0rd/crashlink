class DynamicRetype {
	static function main() {
		var d:Dynamic = 5;
		trace(d);
		d = "hello";
		trace(d);
		d = 3.14;
		trace(d);
		d = [1, 2, 3];
		trace(d);
		var arr:Array<Dynamic> = [1, "two", 3.0, true];
		for (x in arr) {
			trace(x);
		}
	}
}
