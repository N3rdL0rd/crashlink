class ChainedAssign {
    static function main() {
        var a: Int;
        var b: Int;
        var c: Int;
        a = b = c = 5;
        Sys.println(a);
        Sys.println(b);
        Sys.println(c);
        c = 10;
        a = b = c;
        Sys.println(a + "," + b + "," + c);

        var arr = [0, 0, 0];
        var i = 0;
        arr[i] = i = 1;
        Sys.println(arr[0] + "," + arr[1] + "," + arr[2] + " i=" + i);
    }
}
