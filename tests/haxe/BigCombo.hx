enum Shape {
	Circle(r:Float);
	Rect(w:Float, h:Float);
}

class Base {
	public static var counter:Int = 0;
	public var name:String;

	public function new(name:String) {
		this.name = name;
		counter++;
	}

	public function area(s:Shape):Float {
		return switch (s) {
			case Circle(r): 3.14159 * r * r;
			case Rect(w, h): w * h;
		}
	}

	public function makeAdder(base:Float):Float->Float {
		return function(x:Float):Float {
			return x + base + counter;
		};
	}
}

class Derived extends Base {
	public var shapes:Array<Shape> = [];

	public function new(name:String) {
		super(name);
		shapes.push(Circle(1));
		shapes.push(Rect(2, 3));
	}

	public function totalArea():Float {
		var total = 0.0;
		for (s in shapes) {
			total += area(s);
		}
		return total;
	}
}

class BigCombo {
	static function main() {
		var d = new Derived("d1");
		trace(d.totalArea());
		var adder = d.makeAdder(10);
		trace(adder(5));
		var d2 = new Derived("d2");
		trace(Base.counter);
		var adder2 = d2.makeAdder(100);
		trace(adder2(1));
		trace(adder(5));
	}
}
