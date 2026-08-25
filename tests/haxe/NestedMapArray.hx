class NestedMapArray {
	static function main() {
		var m = new Map<String, Array<Int>>();
		m.set("a", [1, 2, 3]);
		var arr = m.get("a");
		arr.push(4);
		trace(m.get("a").length);
		trace(m.get("a")[3]);
		var arr2 = m.get("a");
		arr2[0] = 99;
		trace(m.get("a")[0]);
	}
}
