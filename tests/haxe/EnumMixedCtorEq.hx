enum Shape {
	None;
	Circle(r:Float);
	Rect(w:Float, h:Float);
}

class EnumMixedCtorEq {
	static function main() {
		var a = None;
		var b = None;
		trace(a == b);
		var c = Circle(1.0);
		var d = Circle(1.0);
		trace(c == d);
		var e = Circle(2.0);
		trace(c == e);
		switch (a) {
			case None: trace("none");
			case Circle(r): trace("circle " + r);
			case Rect(w, h): trace("rect " + w + " " + h);
		}
		switch (c) {
			case None: trace("none2");
			case Circle(r): trace("circle2 " + r);
			case Rect(w, h): trace("rect2 " + w + " " + h);
		}
	}
}
