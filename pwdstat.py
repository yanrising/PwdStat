#!/usr/bin/env python

import argparse
import os
import sys

import nltk
import pandas as pd
from colorama import init
from nltk.stem import PorterStemmer
from nltk.tokenize import word_tokenize


def dep_check():
    """
    Checks if nltk dependencies are installed
    """
    try:
        word_tokenize('can you parse me')
    except LookupError:
        nltk.download('punkt')


def message(msg, title=False, stat=False, word=False, banner=False):
    """
    Prints formatted text to CLI
    """

    class Colors:
        BLUE = '\033[94m'
        GREEN = "\033[32m"
        YELLOW = '\033[93m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'

    banner_text = """ __        __   __  ___      ___
|__) |  | |  \ /__`  |   /\   |
|    |/\| |__/ .__/  |  /~~\  |"""

    if title:
        print(f'{Colors.GREEN}{Colors.BOLD}\n[*] {msg}{Colors.ENDC}')
    elif stat:
        print(f'{Colors.BLUE}{msg}{Colors.ENDC}')
    elif word:
        return f'{Colors.YELLOW}{Colors.BOLD}{msg}{Colors.ENDC}{Colors.BLUE}'
    elif banner:
        print(f'{Colors.YELLOW}{banner_text}{Colors.ENDC}')


class PasswordAnalyzer:
    """
    Takes in a list of passwords and analyzes them
    """

    def __init__(self, password_df, filter_lowqual):
        self.compositionType = None
        self.mask = None
        self.alphaLst = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
                         't', 'u', 'v', 'w', 'x', 'y', 'z']
        self.digitsLst = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        self.specialLst = [' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';',
                           '<', '=', '>', '?', '@', '[', '\', \']', '^', '_', '`', '{', '|', '}', '~', ']']
        self.df = password_df
        self.filter = filter_lowqual
        self.filter_percent = 0.0001
        self.viz_label_color = '#3c444c'
        self.viz_tick_color = '#333333'
        self.viz_face_color = '#eeeeee'
        self.viz_data_color1 = '#157394'
        self.viz_data_color2 = '#dc4c4c'

    def classify_passwords(self):
        """
        Generates primary columns per password
        """
        self.df['Class'] = self.df['Password'].apply(lambda x: self.test_class(x)).astype('category')
        self.df['Complexity'] = self.df['Password'].apply(lambda x: self.test_complexity(x)).astype('int8')
        self.df['Length'] = self.df['Password'].apply(len).astype('int8')

    def test_class(self, password_str):
        """
        Ranks passwords by length and complexity into a class score
        :param password_str: password to classify
        :return: str
        """
        digits = 0
        lower = 0
        upper = 0
        special = 0
        length = len(password_str)

        if any(item in password_str for item in self.digitsLst):
            for char in self.digitsLst:
                digits += password_str.count(char)
        if any(item in password_str for item in self.alphaLst):
            for char in self.alphaLst:
                lower += password_str.count(char)
        if any(item in password_str for item in map(str.upper, self.alphaLst)):
            for char in map(str.upper, self.alphaLst):
                upper += password_str.count(char)
        if any(item in password_str for item in self.specialLst):
            for char in self.specialLst:
                special += password_str.count(char)

        if length >= 16:
            if all(v >= 2 for v in [digits, lower, upper, special]):
                return "5: strong"
            elif all(v >= 1 for v in [digits, upper, lower]):
                return "4: great"
            elif all(v >= 1 for v in [digits, lower, special]):
                return "4: great"
            elif all(v >= 1 for v in [digits, upper, special]):
                return "4: great"
            elif all(v >= 1 for v in [lower, upper, special]):
                return "4: great"
            else:
                return "0: subpar"
        elif length >= 12:
            if all(v >= 2 for v in [digits, lower, upper, special]):
                return "4: great"
            elif all(v >= 1 for v in [digits, upper, lower]):
                return "3: good"
            elif all(v >= 1 for v in [digits, lower, special]):
                return "3: good"
            elif all(v >= 1 for v in [digits, upper, special]):
                return "3: good"
            elif all(v >= 1 for v in [lower, upper, special]):
                return "3: good"
            else:
                return "0: subpar"
        elif length >= 8:
            if all(v >= 2 for v in [digits, lower, upper, special]):
                return "3: good"
            elif all(v >= 1 for v in [digits, upper, lower]):
                return "2: okay"
            elif all(v >= 1 for v in [digits, lower, special]):
                return "2: okay"
            elif all(v >= 1 for v in [digits, upper, special]):
                return "2: okay"
            elif all(v >= 1 for v in [lower, upper, special]):
                return "2: okay"
            else:
                return "0: subpar"
        else:
            if all(v >= 1 for v in [digits, upper, lower]):
                return "1: minimum"
            elif all(v >= 1 for v in [digits, lower, special]):
                return "1: minimum"
            elif all(v >= 1 for v in [digits, upper, special]):
                return "1: minimum"
            elif all(v >= 1 for v in [lower, upper, special]):
                return "1: minimum"
            return '0: subpar'

    def test_complexity(self, password_str):
        """
        Ranks the complexity score of the password
        :param password_str: string to rate
        :return: int
        """
        complexity = 0
        if any(item in password_str for item in self.digitsLst):
            complexity += 1
        if any(item in password_str for item in self.alphaLst):
            complexity += 1
        if any(item in password_str for item in map(str.upper, self.alphaLst)):
            complexity += 1
        if any(item in password_str for item in self.specialLst):
            complexity += 1
        return complexity

    def gen_masks(self):
        """
        Generates a Hashcat mask for each password as a new column
        """
        self.df['Mask'] = df['Password'].apply(lambda x: self.make_mask(x)).astype('category')

    def make_mask(self, password_str):
        """
        Generates a Hashcat mask given a string
        :param password_str: string to make mask of
        :return: string
        """
        mask = ''
        for i in password_str:
            if i in self.digitsLst:
                mask += "?d"
            elif i in self.alphaLst:
                mask += "?l"
            elif i in map(str.upper, self.alphaLst):
                mask += "?u"
            elif i in self.specialLst:
                mask += "?s"
            else:
                mask += "?a"
        return mask

    def tokenize_passwords(self):
        """
        Generates a token list for each password as a new column
        :return: pd.DataFrame
        """
        nested_tokens = self.df['Password'].apply(lambda i: self.gen_tokens(i))
        expanded_tokens = [str(item[0]) for item in nested_tokens]
        df_tokens = pd.DataFrame(expanded_tokens).value_counts(ascending=False).to_frame().set_axis(['Count'], axis=1,
                                                                                                    inplace=False).reset_index()
        df_tokens.columns = ['Tokens', 'Count']
        df_tokens.reset_index(drop=True)
        df_tokens = df_tokens[df_tokens['Count'] > 1]
        return df_tokens

    @staticmethod
    def gen_tokens(password_str):
        """
        Tokenizes password into a list
        :param password_str: password to tokenize
        :return: list
        """
        try:
            words = word_tokenize(password_str)
            stemmed_words = [stemmer.stem(word) for word in words]
        except IndexError:
            stemmed_words = ['']
        return stemmed_words

    def analyze_passwords(self):
        """
        Calls primary analysis functions
        """
        self.classify_passwords()
        if self.filter:
            self.df = self.df[self.df['Class'] != '0: subpar']
        else:
            self.df = self.df
        self.gen_masks()

    def lookup_directory(self, compare_dir):
        """
        Looks up a directory and all files inside for comparison
        :param compare_dir: directory full of password lists
        """
        # try error for file load fail
        if compare_dir:
            for i in os.listdir(compare_dir):
                title = 'Is In ' + i
                df_compare = pd.read_table(os.path.join(compare_dir, i), header=None, names=['Password'],
                                           encoding='ISO-8859-1')
                self.lookup_password(df_compare, title)

    def lookup_password(self, compare_df, title):
        """
        Compares two password lists for shared passwords then reports in a new column
        :param compare_df: dataframe to compare against
        :param title: string name of created column
        :return: none (appends to given df)
        """
        df_joined = self.df.merge(compare_df, how='inner', on=['Password'])
        lst_joined = list(set(df_joined.Password.unique().tolist()))

        for q in lst_joined:
            self.df.loc[(self.df['Password'] == q), str(title)] = 1
        self.df[title].fillna(0, inplace=True)
        self.df[title] = self.df[title].astype('int8')

    def report(self):
        """
        Generates aggregate DFs for printing and print stats to CLI
        """
        df_tokens = pwdAnalyzer.tokenize_passwords()

        df_class_agg = self.df.groupby(by='Class').agg(
            {'Password': 'count', 'Complexity': 'mean', 'Length': 'mean'}).reset_index()
        df_class_agg.columns = ['Class', 'Password', 'Complexity', 'Length']
        df_class_agg.reset_index(drop=True)
        df_class_agg.rename(columns={'Password': 'Count'}, inplace=True)

        df_mask_agg = self.df.groupby(by='Mask').agg(
            {'Password': 'count', 'Complexity': 'mean', 'Length': 'mean'}).sort_values(by='Password',
                                                                                       ascending=False).reset_index()
        df_mask_agg.columns = ['Mask', 'Password', 'Complexity', 'Length']
        df_mask_agg.reset_index(drop=True)
        # may need to comment the line below when dealing with small input
        df_mask_agg = df_mask_agg[df_mask_agg['Password'] > 1]
        df_mask_agg.rename(columns={'Password': 'Count'}, inplace=True)

        df_password_agg = self.df.groupby(by='Password').agg(
            {'Password': 'count', 'Complexity': 'mean', 'Length': 'mean'}).rename_axis(None).sort_values(by='Password',
                                                                                                         ascending=False).reset_index()
        df_password_agg.columns = ['Password', 'Count', 'Complexity', 'Length']
        df_password_agg.reset_index(drop=True)

        if self.filter:
            df_mask_agg = df_mask_agg[df_mask_agg['Count'] > round(df_mask_agg.size * self.filter_percent, 0)]
            df_tokens = df_tokens[df_tokens['Count'] > round(df_tokens.size * self.filter_percent, 0)]

        self.print_stats(self.df, 'full')
        self.print_stats(df_password_agg, 'password_agg')
        self.print_stats(df_tokens, 'tokens')
        self.print_stats(df_mask_agg, 'mask_agg')

        if args.output:
            df_tokens.to_csv(os.path.join(args.output, 'common_tokens.csv'), index=False, quoting=3, quotechar='',
                             escapechar='', sep='\t')
            df_class_agg.to_csv(os.path.join(args.output, 'password_classes.csv'), index=False, quoting=3, quotechar='',
                                escapechar='', sep='\t')
            df_mask_agg.to_csv(os.path.join(args.output, 'password_masks.csv'), index=False, quoting=3, quotechar='',
                               escapechar='', sep='\t')
            df_password_agg.to_csv(os.path.join(args.output, 'passwords_agg.csv'), index=False, quoting=3, quotechar='',
                                   escapechar='', sep='\t')

        if args.viz:
            self.print_viz(df_tokens.head(20).set_index('Tokens'), 'bar' , 'Common Password Tokens', 'Count', 'Token', 'common-password-tokens')
            self.print_viz(df_class_agg.set_index('Class')['Count'], 'bar' , 'Password Classes of Cracked Passwords', 'Count', 'Class', 'password-classes')
            self.print_viz(df_class_agg.set_index('Class').drop(columns=['Count', 'Complexity']), 'box' , 'Average Length of Cracked Passwords', 'Count', 'Length', 'avg-password-length')
            self.print_viz(df_mask_agg.head(20).set_index('Mask').drop(columns=['Complexity', 'Length']), 'bar' , 'Common Password Masks', 'Count', 'Mask', 'common-password-masks')


    def print_stats(self, df2print, type_str):
        """
        Prints DF stats to CLI
        :param df2print: pd.DataFrame to print
        :param type_str: string that contains the type of DF being passed
        """
        if type_str == 'full':
            message('Password Stats:', title=True)
            message('Reminder the sample is ONLY cracked passwords and data points should be reflected on as so',
                    stat=True)
            message(
                'Microsoft minimum password complexity requires 3 of the following criteria: 1 lowercase, 1 uppercase, 1 digit, and 1 special character.\n',
                stat=True)
            message('There are ' + message(str(len(df2print)),
                                           word=True) + ' passwords in the sample and the average complexity is ' + message(
                str(round(df2print['Complexity'].mean(), 1)) + '/4',
                word=True) + ' and the average length is ' + message(
                str(round(df2print['Length'].mean(), 1)), word=True), stat=True)
            message(message(str(df2print['Class'][df2print['Class'] == '0: subpar'].count()),
                            word=True) + ' passwords were considered subpar and did not meet minimum password requirements and had an average length of ' + message(
                str(round(df2print['Length'][df2print['Class'] == '0: subpar'].mean(), 1)), word=True), stat=True)
            message(message(str(df2print['Class'][df2print['Class'] == '1: minimum'].count()),
                            word=True) + ' passwords met the minimum complexity requirements and had an average length of ' + message(
                str(round(df2print['Length'][df2print['Class'] == '1: minimum'].mean(), 1)), word=True), stat=True)
            message(message(str(df2print['Class'][df2print['Class'] == '2: okay'].count()),
                            word=True) + ' passwords met or exceeded minimum complexity requirements and had an average length of ' + message(
                str(round(df2print['Length'][df2print['Class'] == '2: okay'].mean(), 1)), word=True), stat=True)
            message(message(str(df2print['Class'][df2print['Class'] == '3: good'].count()),
                            word=True) + ' passwords met or exceeded minimum complexity requirements and had a strong password length averaging ' + message(
                str(round(df2print['Length'][df2print['Class'] == '3: good'].mean(), 1)), word=True), stat=True)
            message(message(str(df2print['Class'][df2print['Class'] == '4: great'].count()),
                            word=True) + ' passwords met or exceeded minimum complexity requirements and had a very strong password length averaging ' + message(
                str(round(df2print['Length'][df2print['Class'] == '4: great'].mean(), 1)), word=True), stat=True)
            message(message(str(df2print['Class'][df2print['Class'] == '5: strong'].count()),
                            word=True) + ' passwords well exceeded minimum complexity requirements and had a fortified password length averaging ' + message(
                str(round(df2print['Length'][df2print['Class'] == '5: strong'].mean(), 1)), word=True), stat=True)

            if args.compare:
                message('Password Lookup:', title=True)
                for i in os.listdir(args.compare):
                    try:
                        message(message(str(df2print['Is In ' + str(i)].sum()),
                                        word=True) + ' passwords were also in ' + message(str(i), word=True), stat=True)
                    except KeyError:
                        pass

        elif type_str == 'password_agg':
            message('Reused Passwords:', title=True)
            for i in range(0, 8):
                if df2print.empty:
                    message('Empty input file for the function', stat=True)
                    break
                message(message(str(df2print['Password'].iloc[i]), word=True) + ' occurred ' + message(
                    str(df2print['Count'].iloc[i]), word=True) + ' times', stat=True)

        elif type_str == 'tokens':
            message('Common Tokens and Words in Passwords:', title=True)
            for i in range(0, 8):
                if df2print.empty:
                    message('Empty input file for the function', stat=True)
                    break
                message('The token ' + message(str(df2print['Tokens'].iloc[i]), word=True) + ' was used ' + message(
                    str(df2print['Count'].iloc[i]), word=True) + ' times', stat=True)

        elif type_str == 'mask_agg':
            message('Common Password Masks:', title=True)
            for i in range(0, 8):
                if df2print.empty:
                    message('Empty input file for the function. Note masks that occurred only once are dropped.',
                            stat=True)
                    break
                message(message(str(df2print['Count'].iloc[i]), word=True) + ' passwords used the mask ' + message(
                    str(df2print['Mask'].iloc[i]), word=True), stat=True)
                try:
                    message('For example: ' + message(
                        str(self.df['Password'][self.df['Mask'] == str(df2print['Mask'].iloc[i])].iloc[0]),
                        word=True) + ', ' + message(
                        str(self.df['Password'][self.df['Mask'] == str(df2print['Mask'].iloc[i])].iloc[1]),
                        word=True) + ', and ' + message(
                        str(self.df['Password'][self.df['Mask'] == str(df2print['Mask'].iloc[i])].iloc[2]), word=True),
                            stat=True)
                except IndexError:
                    try:
                        message('For example: ' + message(
                            str(self.df['Password'][self.df['Mask'] == str(df2print['Mask'].iloc[i])].iloc[0]),
                            word=True) + ', ' + message(
                            str(self.df['Password'][self.df['Mask'] == str(df2print['Mask'].iloc[i])].iloc[1]),
                            word=True))
                    except IndexError:
                        message('For example: ' + message(
                            str(self.df['Password'][self.df['Mask'] == str(df2print['Mask'].iloc[i])].iloc[0]),
                            word=True))

    def print_viz(self, df, chart_type, title, xlabel, ylabel, output_name):

        if chart_type == 'bar':
            ax = df.plot(kind="barh", fontsize=5, color=self.viz_data_color1, alpha=0.5)
        elif chart_type == 'box':
           ax = df.plot.box(vert=False)
        
        ax.set_title(title, color=self.viz_label_color)
        ax.set_xlabel(xlabel, color=self.viz_label_color)
        ax.set_ylabel(ylabel, color=self.viz_label_color)
        ax.tick_params(labelcolor=self.viz_tick_color)
        ax.set_facecolor(self.viz_face_color)
        ax.figure.savefig(str(output_name) + '.pdf')

if __name__ == '__main__':
    # colorama
    init()
    parser = argparse.ArgumentParser(
        description='Tool for identifying systemic password usage, creating password masks, and analyzing cracked password samples with human readable statistics')
    parser.add_argument("-i", "--input", action="store", default='yourfilenamehere', help='Input list of passwords.')
    parser.add_argument("-c", "--compare", action="store", default=False,
                        help='Directory of lists to compare against.')
    parser.add_argument("-o", "--output", action="store", default=False,
                        help="Prints CSV files to directory. The default is cwd.")
    parser.add_argument("-f", "--filter", action="store_true", default=False,
                        help="Filter subpar from results and bottom 0.01 percent of masks and tokens.")
    parser.add_argument("-q", "--quiet", action="store_true", default=False,
                        help="Hides banner")
    parser.add_argument("-v", "--viz", action="store_true", default=False,
                        help="Creates visuals of data in output directory.")

    dep_check()
    pd.set_option('mode.chained_assignment', None)
    args = parser.parse_args()
    stemmer = PorterStemmer()

    if args.output:
        if args.output == '-':
            args.output = os.getcwd()
    if args.compare:
        if args.compare == '-':
            args.output = os.getcwd()

    if not sys.stdin.isatty() and not args.input:
        args.input = sys.stdin

    try:
        if not args.quiet:
            message('', banner=True)
        df = pd.read_table(args.input, header=None, names=['Password'], quoting=3, on_bad_lines='skip')
        df['Password'] = df['Password'].astype(str)
    except FileNotFoundError:
        print('No input file found')
        exit()

    pwdAnalyzer = PasswordAnalyzer(df, args.filter)
    pwdAnalyzer.analyze_passwords()
    pwdAnalyzer.lookup_directory(args.compare)
    pwdAnalyzer.report()
