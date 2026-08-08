interface Shape {
    function area(): Float;
    function name(): String;
}

class Circle implements Shape {
    var r: Float;
    public function new(r: Float) { this.r = r; }
    public function area(): Float { return 3.14159 * r * r; }
    public function name(): String { return "circle"; }
}

class Square implements Shape {
    var s: Float;
    public function new(s: Float) { this.s = s; }
    public function area(): Float { return s * s; }
    public function name(): String { return "square"; }
}

class InterfaceSharedMethod {
    static function describe(sh: Shape): String {
        return sh.name() + ":" + sh.area();
    }

    static function main() {
        var shapes: Array<Shape> = [new Circle(2), new Square(3)];
        for (sh in shapes) {
            Sys.println(describe(sh));
        }
    }
}
