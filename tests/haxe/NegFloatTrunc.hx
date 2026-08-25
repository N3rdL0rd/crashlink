class NegFloatTrunc {
	static function main() {
		trace(Std.int(-1.5));
		trace(Std.int(-1.9));
		trace(Std.int(1.9));
		trace(Std.int(-0.5));
		var a = -7.0 / 2.0;
		trace(a);
		trace(Std.int(a));
		var nan = Math.NaN;
		trace(nan == nan);
		trace(Math.isNaN(nan));
		var inf = Math.POSITIVE_INFINITY;
		trace(inf > 1000000.0);
		trace(-inf < -1000000.0);
		trace(Std.int(inf) == Std.int(inf));
	}
}
