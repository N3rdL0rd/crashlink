class ArrayAllocCase {
    static function makeEmpty(): Array<Dynamic> {
        return [];
    }

    static function makeNew(): Array<Dynamic> {
        return new Array<Dynamic>();
    }

    public static function main(): Void {
        var a = makeEmpty();
        var b = makeNew();
        a.push(1);
        b.push(2);
    }
}
