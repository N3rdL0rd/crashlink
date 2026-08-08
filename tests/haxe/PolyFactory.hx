class Shape {
    public function new() {}
    public function area(): Float {
        return 0.0;
    }
    public function name(): String {
        return "Shape";
    }
}

class Circle extends Shape {
    var r: Float;
    public function new(r: Float) {
        super();
        this.r = r;
    }
    override public function area(): Float {
        return 3.14159 * r * r;
    }
    override public function name(): String {
        return "Circle";
    }
}

class Square extends Shape {
    var s: Float;
    public function new(s: Float) {
        super();
        this.s = s;
    }
    override public function area(): Float {
        return s * s;
    }
    override public function name(): String {
        return "Square";
    }
}

class ShapeFactory {
    public static function create(kind: String, size: Float): Shape {
        return switch (kind) {
            case "circle": new Circle(size);
            case "square": new Square(size);
            default: new Shape();
        };
    }
}

class PolyFactory {
    static function main() {
        var kinds = ["circle", "square", "other"];
        var total = 0.0;
        for (k in kinds) {
            var s = ShapeFactory.create(k, 2.0);
            trace(s.name());
            trace(s.area());
            total += s.area();
        }
        trace(total);

        var shapes: Array<Shape> = [];
        for (k in kinds) shapes.push(ShapeFactory.create(k, 1.5));
        for (s in shapes) trace(Std.string(s.name()) + ":" + Std.string(s.area()));
    }
}
