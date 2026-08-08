class NumFormatMix {
	static function main() {
		var i:Int = 1;
		var f:Float = 1.0;
		var f2:Float = 1;
		var big:Float = 1e20;
		var small:Float = 1e-10;
		trace(Std.string(i));
		trace(Std.string(f));
		trace(Std.string(f2));
		trace(Std.string(big));
		trace(Std.string(small));
		trace(i + "");
		trace(f + "");
		var arr:Array<Float> = [1, 2.5, 3];
		trace(Std.string(arr[0]));
	}
}
