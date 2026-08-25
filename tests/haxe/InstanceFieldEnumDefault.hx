enum Shape {
	Circle(r:Float);
	Square(s:Float);
}

class Holder {
	public var shape:Shape = Circle(1.5);
	public var items:Array<Int> = [1, 2, 3];
	public var nested:Array<Array<Int>> = [[1, 2], [3, 4]];
	public function new() {}
}

class InstanceFieldEnumDefault {
	static function main() {
		var h = new Holder();
		trace(h.shape);
		trace(h.items);
		trace(h.nested);
		h.items.push(4);
		var h2 = new Holder();
		trace(h2.items); // must NOT show 4 - fresh array each instance
	}
}
