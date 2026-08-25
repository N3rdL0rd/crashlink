enum Shape {
	Circle(r:Float);
	Square(side:Float);
	Point;
}

class EnumMixedSwitch {
	static function area(s:Shape):Float {
		return switch (s) {
			case Circle(r): Math.PI * r * r;
			case Square(side): side * side;
			case Point: 0.0;
		}
	}

	static function main() {
		var shapes = [Circle(2.0), Square(3.0), Point];
		for (s in shapes) {
			trace(area(s));
		}
		var a = Circle(1.0);
		var b = Circle(1.0);
		trace(a == b);
		var c = a;
		trace(a == c);
		trace(Point == Point);
		trace(Std.string(Circle(1.0)));
		trace(Std.string(Point));
	}
}
