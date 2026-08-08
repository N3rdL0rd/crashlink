class StringSlice {
	static function main() {
		var s = "hello world";
		trace(s.substr(-5));
		trace(s.substr(-5, 3));
		trace(s.substring(-3, 5));
		trace(s.charAt(-1));
		trace(s.charAt(100));
		trace("".length);
		trace("" == "");
		trace("a" < "b");
		trace("Z" < "a");
		trace(s.split("").length);
		var buf = new StringBuf();
		buf.add("x");
		buf.add(1);
		buf.add(true);
		trace(buf.toString());
	}
}
