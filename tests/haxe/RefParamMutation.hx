class Box {
    public var v:Int;
    public function new(v:Int) { this.v = v; }
}

class RefParamMutation {
    static function bump(arr:Array<Int>, b:Box) {
        arr[0] = arr[0] + 1;
        arr.push(arr.length);
        b.v = b.v * 10;
    }

    static function main() {
        var a = [1, 2, 3];
        var b = new Box(5);
        bump(a, b);
        bump(a, b);
        trace(a);
        trace(b.v);
    }
}
