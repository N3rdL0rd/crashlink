class ArrayLiteralIdentity {
	static function main() {
		var a = [1, 2, 3];
		var b = [1, 2, 3];
		trace(a == b);
		trace(a == a);
		var o1 = { x: 1, y: 2 };
		var o2 = { x: 1, y: 2 };
		trace(o1 == o2);
		trace(o1 == o1);
		var arr = [a, b];
		trace(arr[0] == a);
		trace(arr[0] == b);
	}
}
