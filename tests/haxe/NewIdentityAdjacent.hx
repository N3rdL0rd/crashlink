class Pt {
	public var x: Int;
	public var y: Int;
	public function new(x: Int, y: Int) {
		this.x = x;
		this.y = y;
	}
}

class NewIdentityAdjacent {
	static function main() {
		var a = new Pt(1, 2);
		var b = new Pt(1, 2);
		trace(a == b);
		trace(a == a);
		a.x = 99;
		trace(a.x);
		trace(b.x);
	}
}
