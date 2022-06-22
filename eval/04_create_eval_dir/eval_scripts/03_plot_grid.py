# coding: utf-8

import os
from datetime import timedelta
import re
import json

import pandas as pd
import seaborn as sns
from matplotlib.ticker import PercentFormatter, LinearLocator


import matplotlib as mpl
from seaborn.utils import _check_argument, adjust_legend_subtitles, _draw_figure

# Monkey-patch legend plotting
def add_legend(self, legend_data=None, title=None, label_order=None,
               adjust_subtitles=False, **kwargs):
    """Draw a legend, maybe placing it outside axes and resizing the figure.
    Parameters
    ----------
    legend_data : dict
        Dictionary mapping label names (or two-element tuples where the
        second element is a label name) to matplotlib artist handles. The
        default reads from ``self._legend_data``.
    title : string
        Title for the legend. The default reads from ``self._hue_var``.
    label_order : list of labels
        The order that the legend entries should appear in. The default
        reads from ``self.hue_names``.
    adjust_subtitles : bool
        If True, modify entries with invisible artists to left-align
        the labels and set the font size to that of a title.
    kwargs : key, value pairings
        Other keyword arguments are passed to the underlying legend methods
        on the Figure or Axes object.
    Returns
    -------
    self : Grid instance
        Returns self for easy chaining.
    """
    # Find the data for the legend
    if legend_data is None:
        legend_data = self._legend_data
    if label_order is None:
        if self.hue_names is None:
            label_order = list(legend_data.keys())
        else:
            label_order = list(map(utils.to_utf8, self.hue_names))

    blank_handle = mpl.patches.Patch(alpha=0, linewidth=0)
    handles = [legend_data.get(l, blank_handle) for l in label_order]
    title = self._hue_var if title is None else title
    title_size = mpl.rcParams["legend.title_fontsize"]

    # Unpack nested labels from a hierarchical legend
    labels = []
    for entry in label_order:
        if isinstance(entry, tuple):
            _, label = entry
        else:
            label = entry
        labels.append(label)

    # Set default legend kwargs
    kwargs.setdefault("scatterpoints", 1)

    if self._legend_out:

        kwargs.setdefault("frameon", False)
        kwargs.setdefault("loc", "center right")
        kwargs['ncol'] = 8
        kwargs['loc'] = 'upper center'
        kwargs['bbox_to_anchor'] = (0.5, 0)

        # Draw a full-figure legend outside the grid
        figlegend = self._figure.legend(handles, labels, **kwargs)

        self._legend = figlegend
        figlegend.set_title(title, prop={"size": title_size})

        if adjust_subtitles:
            adjust_legend_subtitles(figlegend)

        # Draw the plot to set the bounding boxes correctly
        _draw_figure(self._figure)

        # Calculate and set the new width of the figure so the legend fits
        legend_height = figlegend.get_window_extent().height / self._figure.dpi
        fig_width, fig_height = self._figure.get_size_inches()
        self._figure.set_size_inches(fig_width, fig_height + legend_height)

        # Draw the plot again to get the new transformations
        _draw_figure(self._figure)

        # Now calculate how much space we need on the bottom side
        legend_height = figlegend.get_window_extent().height / self._figure.dpi
        space_needed = legend_height / (fig_height + legend_height)
        margin = .04 if self._margin_titles else .01
        self._space_needed = margin + space_needed
        bottom = self._space_needed  # 1 - self._space_needed

        # Place the subplot axes to give space for the legend
        self._figure.subplots_adjust(bottom=bottom)
        self._tight_layout_rect[3] = bottom  # TODO: figure out correct index

    else:
        # Draw a legend in the first axis
        ax = self.axes.flat[0]
        kwargs.setdefault("loc", "best")

        leg = ax.legend(handles, labels, **kwargs)
        leg.set_title(title, prop={"size": title_size})
        self._legend = leg

        if adjust_subtitles:
            adjust_legend_subtitles(leg)

    return self


sns.FacetGrid.add_legend = add_legend

# set context
sns.set_context("paper", font_scale=1.1, rc={'text.usetex': True})
# and style
sns.set_style("whitegrid")

# number of columns (7 appears to work nicely for a full-width figure)
N_COLUMNS = 7


def _load_conf(load_file):
    config_path = os.path.join(os.path.dirname(load_file), "fuzz.cfg")
    with open(config_path) as f:
        config = json.load(f)
    timeout = parse_timeout(config.get("timeout"))
    args = parse_args(config.get("args"))
    return {**args, "timeout": timeout, "package": config.get("pkg"), "program": config.get("target"),
            "port": int(config.get("port"))}


def parse_timeout(timeout_str):
    timeout_re = re.compile(
        r"((?P<hours>\d+)h)?((?P<minutes>\d+)m)?((?P<seconds>\d+)s)?"
    )
    match = timeout_re.match(timeout_str)
    if not match:
        return None
    return timedelta(
        **{k: int(v) for k, v in match.groupdict().items() if v}
    ).total_seconds()


def load_df(basedir, max_ts=None):
    pickle_file = os.path.join(basedir, f".plotdata_{max_ts}.pkl")
    if os.path.exists(pickle_file):
        try:
            df = pd.read_pickle(pickle_file)
            return df
        except:
            pass

    logfile = "angora.log"
    load_files = [
        os.path.join(root, logfile)
        for root, dirs, files in os.walk(basedir)
        if logfile in files
    ]
    records = []
    for run, load_file in enumerate(sorted(load_files)):
        try:
            records.append(_load_single_df(load_file, run, max_ts))
        except ValueError as e:
            print(f'Skipping file {load_file} ({e})')
    df = pd.DataFrame.from_records(records)
    df.to_pickle(pickle_file)
    return df


def _load_single_df(load_file, run, max_ts=None):
    df = pd.read_csv(load_file, index_col="secs")
    conf = _load_conf(load_file)
    if max_ts:
        if max_ts > conf["timeout"]:
            raise ValueError(f"Error, max_ts above timeout {conf['timeout']}")
        conf["timeout"] = max_ts
        df = df[df.index < max_ts]
    # stats we care about:
    # 1. time to first response (best_amp > 0)
    # 2. time to first amp (best_amp > 1)
    # 3. time to max amp
    # 4. max_amp
    s = df["best_amp"]
    tt_first_response = s[s > 0].idxmin() if not s[s > 0].empty else None
    tt_first_amp = s[s > 1].idxmin() if not s[s > 1].empty else None
    tt_max_amp = s.idxmax() if not s.empty else None
    max_amp = s.max() if not s.empty else None
    return {
        **conf,
        "tt_first_response": tt_first_response,
        "tt_first_amp": tt_first_amp,
        "tt_max_amp": tt_max_amp,
        "max_amp": max_amp,
        "run": run,
    }


def parse_args(args_str):
    args = {
        "startup_time_limit": 500000,
        "response_time_limit": 500000,
        "disable_listen_ready": False,
        "early_termination": "full",
        "disable_amp_mutation": False,
        "disable_exploitation": False,
    }
    for tok in args_str.split():
        if not tok.strip().startswith("-a="):
            continue
        tok = tok.split("=", maxsplit=1)[1].strip().lstrip("-")
        if "=" in tok:
            k, v = tok.split("=", maxsplit=1)
            try:
                v = int(v)
            except ValueError:
                pass
            args[k] = v
        else:
            args[tok] = True
    return args


def to_human_time(microsec):
    SUFFIXES = ["µs", "ms", "s"]
    value = microsec
    for suffix in SUFFIXES:
        if value >= 1000 and suffix != SUFFIXES[-1]:
            value /= 1000
        else:
            break
    return f"{value:.0f}{suffix}"


def gen_target_labels(df):
    return df['program'].str.rsplit('/', n=1).str.get(1) + ':' + df['port'].astype('str') + '\n(' + df['package'] + ')'


def gen_conf_labels(df):
    labels = {i: [] for i in df.index}
    if df["early_termination"].nunique(dropna=False) > 1:
        for idx, row in df.iterrows():
            mode = "UDP aware" if row["early_termination"] == "full" else "static"
            timeout = to_human_time(row["response_time_limit"])
            labels[idx].append(f"{mode} {timeout}")
    if df["disable_amp_mutation"].nunique(dropna=False) > 1:
        for idx, row in df.iterrows():
            if row["disable_amp_mutation"]:
                labels[idx].append("amp. maximization disabled")
            else:
                labels[idx].append("amp. maximization enabled")
    return pd.Series({i: ", ".join(l) for i, l in labels.items()})


def load(result_dir, timeout):
    df = load_df(result_dir, timeout)
    df["target_label"] = gen_target_labels(df)
    df_amp_operator = df[df["early_termination"] == "full"].copy()
    df_amp_operator["conf_label"] = gen_conf_labels(df_amp_operator)
    df_termination = df[df["disable_amp_mutation"] == False].copy()
    df_termination["conf_label"] = gen_conf_labels(df_termination)

    return df_amp_operator, df_termination


def do_plot(df, timeout, result_dir, kind='response', add_zero=False):
    # Filter out inactive services
    active_services = df.groupby(["target_label"])["tt_first_response"].count() > 0
    df = df[df["target_label"].isin(active_services[active_services].index)].copy()

    # Compute ranks as percentiles, but keep NA-values to the end (which, confusingly, corresponds to the na_option "bottom")
    # max? min? dense?
    df[f"tt_first_{kind}_run_pct"] = df.groupby(["target_label", "conf_label"])[f"tt_first_{kind}"].rank(method="first",
                                                                                                         pct=True,
                                                                                                         na_option="bottom")

    if add_zero:
        # Add 0-data to get line from origin
        extra_rows = df.groupby(["target_label", "conf_label"]).first().copy()
        extra_rows[f'tt_first_{kind}'] = 0.0
        extra_rows[f'tt_first_{kind}_run_pct'] = 0.0
        extra_rows['run'] += df['run'].max() + 1
        df_plot = pd.concat([df, extra_rows.reset_index()], ignore_index=True)
    else:
        df_plot = df

    if df_plot.empty:
        print("No data to plot, skipping...")
        return

    col_order = list(df.groupby(["target_label"]).first().sort_values(["package", "program", "port"]).index)
    hue_order = list(df.groupby(["conf_label"]).first().sort_values(["early_termination", "response_time_limit"],
                                                                    ascending=[False, True]).index)
    # Plot time to first response
    fg = sns.relplot(kind='line', x=f"tt_first_{kind}_run_pct", y=f"tt_first_{kind}", hue="conf_label",
                     col="target_label", col_wrap=N_COLUMNS, data=df_plot, style="conf_label", dashes=False,
                     markers=['o', 's', 'P', 'v', 'd', 'X'][:len(hue_order)], linestyle='--', height=2, aspect=1, col_order=col_order,
                     hue_order=hue_order, markersize=8)

    # Make nice and save a figure
    fg.set(xlim=(0, 1), xlabel="Percentage of Runs", ylabel=f"Time to first\n{kind} (s)", ylim=(-.1, timeout))
    fg.set_titles(col_template="{col_name}")
    for i, ax in enumerate(fg.axes.flat):
        ax.xaxis.set_major_locator(LinearLocator(numticks=3))
        ax.xaxis.set_major_formatter(PercentFormatter(xmax=1))
        if i % N_COLUMNS:
            ax.set_ylabel(None)

    fg._legend.set_title(None)  # 'configuration')
    for p in fg._legend.get_lines():
        p.set_markeredgecolor("white")
        p.set_markersize(8)

    sns.utils.plt.savefig(os.path.join(result_dir, f"first_{kind}_grid.pdf"), bbox_inches='tight')

    # Recale y to symlog, save again
    fg.set(yscale="symlog", ylim=(-.5, timeout))
    sns.utils.plt.savefig(os.path.join(result_dir, f"first_{kind}_grid_log.pdf"), bbox_inches='tight')
    sns.utils.plt.close()


def do_plot_amp(df, result_dir, add_zero=False):
    # Filter out inactive services
    active_services = (df.groupby(["target_label"])["tt_first_response"].count() > 0) & (
            df.groupby(["target_label"])["max_amp"].max() > 1)
    df = df[df["target_label"].isin(active_services[active_services].index)].copy()

    # Compute ranks as percentiles, but keep NA-values to the end (which, confusingly, corresponds to the na_option "bottom")
    df["max_amp_run_pct"] = df.groupby(["target_label", "conf_label"])["max_amp"].rank(method="first", pct=True,
                                                                                       na_option="bottom")
    if add_zero:
        # Add 0-data to get line from origin
        extra_rows = df.groupby(["target_label", "conf_label"]).first().copy()
        extra_rows['max_amp'] = 0.0
        extra_rows['max_amp_run_pct'] = 0.0
        extra_rows['run'] += df['run'].max() + 1
        df_plot = pd.concat([df, extra_rows.reset_index()], ignore_index=True)
    else:
        df_plot = df

    if df_plot.empty:
        print("No data to plot, skipping...")
        return

    col_order = list(df.groupby(["target_label"]).first().sort_values(["package", "program", "port"]).index)
    hue_order = list(df.groupby(["conf_label"]).first().sort_index(ascending=True).index)
    # Plot time to first response
    fg = sns.relplot(kind='line', x="max_amp_run_pct", y="max_amp", hue="conf_label", col="target_label",
                     col_wrap=N_COLUMNS, data=df_plot, style="conf_label", dashes=False, markers=['o', 'X'][:len(hue_order)],
                     linestyle='--', height=2, aspect=1, col_order=col_order, hue_order=hue_order, markersize=9,
                     facet_kws={'sharey': False})

    # Make nice and save a figure
    fg.set(xlim=(0, 1), xlabel="Percentage of Runs", ylabel="$\max(BAF_{L2})$")
    fg.set_titles(col_template="{col_name}")
    for i, ax in enumerate(fg.axes.flat):
        ax.xaxis.set_major_locator(LinearLocator(numticks=3))
        ax.xaxis.set_major_formatter(PercentFormatter(xmax=1))
        if i % N_COLUMNS:
            ax.set_ylabel(None)

    fg._legend.set_title(None)  # 'configuration')
    for p in fg._legend.get_lines():
        p.set_markeredgecolor("white")
        p.set_markersize(8)

    sns.utils.plt.savefig(os.path.join(result_dir, "max_amp_grid.pdf"), bbox_inches='tight')

    # Recale y to symlog, save again
    fg.set(yscale="symlog")
    sns.utils.plt.savefig(os.path.join(result_dir, "max_amp_grid_log.pdf"), bbox_inches='tight')
    sns.utils.plt.close()


def plot(result_dir, timeout):
    df_amp_operator, df_termination = load(result_dir, timeout)

    do_plot_amp(df_amp_operator, result_dir, True)

    do_plot(df_termination, timeout, result_dir, 'response', True)
    do_plot(df_termination, timeout, result_dir, 'amp', True)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('result_dir')
    parser.add_argument('timeout', type=int, help='only consider runs that ran for at least <timeout> seconds')
    args = parser.parse_args()
    plot(args.result_dir, args.timeout)


if __name__ == '__main__':
    main()
