class ArrayRmwAcrossCalls {
    static function sideEffect(x:Int):Void {
        Sys.println("side:" + x);
    }

    static function main() {
        var arr = [1, 2, 3, 4, 5];
        var i = 2;
        var tmp = arr[i];
        sideEffect(tmp);
        sideEffect(99);
        arr[i] = tmp + 10;
        sideEffect(arr[i]);
        Sys.println(arr.join(","));

        // plain local RMW spanning calls, no closures
        var a = 5;
        var b = a * 2;
        sideEffect(b);
        unrelated();
        a = a + b;
        sideEffect(a);
        Sys.println(a + "," + b);
    }

    static function unrelated():Void {
        Sys.println("unrelated");
    }
}
