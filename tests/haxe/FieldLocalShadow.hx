class FieldLocalShadow {
    var x: Int;
    static var sx: Int = 100;

    function new(x: Int) {
        this.x = x;
    }

    function bump(): Int {
        var x = this.x + 1;
        this.x = x * 2;
        return x;
    }

    static function bumpStatic(): Int {
        var sx = sx + 1;
        FieldLocalShadow.sx = sx * 2;
        return sx;
    }

    static function main() {
        var f = new FieldLocalShadow(5);
        var r1 = f.bump();
        Sys.println(r1 + " " + f.x);
        var r2 = bumpStatic();
        Sys.println(r2 + " " + sx);
    }
}
