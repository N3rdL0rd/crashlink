class Clazz extends Parent {
    var b: Int;

    public function new() {
        this.b = 10;
    }

    static function main() {
        var c = new Clazz();
        c.b = 15;
        var a = c.b;
        c.method();
    }

    function method(): Int {
        this.b = 18;
        return 42;
    }
}

class Parent {
    var a: Int;
}
