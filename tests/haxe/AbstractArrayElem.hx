abstract Meter(Float) from Float to Float {
	public function new(v:Float) {
		this = v;
	}
	@:op(A + B) public function add(other:Meter):Meter {
		return new Meter(this + (other : Float));
	}
}

class AbstractArrayElem {
	static function main() {
		var arr:Array<Meter> = [new Meter(1.0), new Meter(2.5), new Meter(3.0)];
		var total = new Meter(0);
		for (m in arr) {
			total = total + m;
		}
		trace((total : Float));
		arr[1] = new Meter(10.0);
		trace((arr[1] : Float));
		var sum2 = arr[0] + arr[1];
		trace((sum2 : Float));
	}
}
