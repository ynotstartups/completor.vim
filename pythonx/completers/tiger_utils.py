from thefuzz import fuzz

MOCK_PREFIX = 'mock_'
TEST_PREFIX = 'test_'

def check_subseq_fuzzy(src: str, target: str) -> tuple[int, str] | None:
    """Check if src is a subsequence of target.

    1. support completion when I want to mock a function in python
       in the following case
        
        @mock.patch("foo.bar.export_duplicates")
        def test_foo(self, mock_e?):

    :param src:    what user types
    :param target: a word in buffer

    :return score:
    """
    if not src:
        return None

    # when we want to complete `test_`, we are looking for a function not other
    # test names
    if src.startswith(TEST_PREFIX) and target.startswith(TEST_PREFIX):
        return None
    elif src.startswith(MOCK_PREFIX) and target.startswith(MOCK_PREFIX):
        return None

    modified_src = src.removeprefix(MOCK_PREFIX).removeprefix(TEST_PREFIX)

    # first character must match, case insensitve
    # if modified_src[0].lower() != target[0].lower():
    #     return None

    # if length of what user wants to complete is longer then target
    # remove this target
    target_length = len(target)
    if len(modified_src) > target_length:
        return None

    # modify the target to boost the score

    # Old Version
    # modified_target = target.replace("_", "").lower()

    # optimise for searching for typing `asscall` to return `_assert_called_once_with`
    # instead of returning `assertEqual`
    # because I realised that I tend to type in the first few characters of
    # each word to look for a longer word
    modified_target = "".join([word[:3] for word in target.split('_')])

    fuzz_ratio_score = fuzz.ratio(modified_src, modified_target)

    score = fuzz_ratio_score

    # boost score by the length of target
    # prioritise completing long words
    score += min(target_length, 10)

    if src.startswith(MOCK_PREFIX) and not target.startswith(MOCK_PREFIX):
        return -1 * score, f"{MOCK_PREFIX}{target}"
    elif src.startswith(TEST_PREFIX):
        # when targets is a private function `_foo_bar`
        # we remove the additional `_`
        return -1 * score, f"{TEST_PREFIX}{target.removeprefix('_')}"
    else:
        return -1 * score, target

def check_subseq(src, target):
    """Check if src is a subsequence of target.

    this check_subseq has the nice property that the string length similarity doesn't matter

    I want a fuzzy algorithm that the string length similarity doesn't matter
    """
    if not src:
        return 0

    score = i = 0
    src, target = src.lower(), target.lower()
    src_len, target_len = len(src), len(target)
    for index, e in enumerate(target):
        if src_len - i > target_len - index:
            return
        if e != src[i]:
            continue
        if index == 0:
            score = -999
        score += index
        i += 1
        if i == src_len:
            return score

def test_check_subseq():
    assert check_subseq("abc", "abc") == -996
    assert check_subseq("abc", "abcde") == -996

def test_check_subseq_fuzzy():
    assert check_subseq_fuzzy("abc", "abc") == (-100 - 3, "abc")
    assert check_subseq_fuzzy("mock_abc", "abc") == (-100 - 3, "mock_abc")
