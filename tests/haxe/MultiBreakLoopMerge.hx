class MultiBreakLoopMerge {
    static function find(arr:Array<Int>):Int {
        var found = -1;
        var i = 0;
        while (i < arr.length) {
            if (arr[i] == 42) {
                found = i;
                break;
            }
            if (arr[i] < 0) {
                found = -100;
                break;
            }
            if (arr[i] > 1000) {
                found = -200;
                break;
            }
            i++;
        }
        return found;
    }

    static function main() {
        trace(find([1,2,42,3]));
        trace(find([1,-5,2]));
        trace(find([1,2000,2]));
        trace(find([1,2,3]));
    }
}
