function fig_exp2_deadline_miss()
%FIG_EXP2_DEADLINE_MISS  Policy engine: offered rate vs 1 s deadline-miss %.
% Reads exp2_evaluator_scaling.csv. Clearest view of the overload transition.
% Self-contained. Shaded stable/marginal/saturated regions.

% ---- STYLE ----
col=[0.031 0.318 0.612];
band_stable=[0.780 0.914 0.753]; band_marg=[0.996 0.890 0.569]; band_sat=[0.988 0.682 0.569];
stable_max=22.5; marg_max=27.5;   % edit region cutoffs
lw=1.8; ms=6; fsize=11; figsize=[0 0 6.0 3.8];
% ---------------
here=fileparts(mfilename('fullpath'));
T=readtable(fullfile(here,'exp2_evaluator_scaling.csv'));
r=T.offered_rate_eval_s; rmax=max(r);
fig=figure('Units','inches','Position',figsize,'Color','w'); ax=axes(fig); hold(ax,'on');
patch(ax,[0 stable_max stable_max 0],[-3 -3 100 100],band_stable,'EdgeColor','none','FaceAlpha',0.5,'DisplayName','stable');
patch(ax,[stable_max marg_max marg_max stable_max],[-3 -3 100 100],band_marg,'EdgeColor','none','FaceAlpha',0.5,'DisplayName','marginal');
patch(ax,[marg_max rmax+2 rmax+2 marg_max],[-3 -3 100 100],band_sat,'EdgeColor','none','FaceAlpha',0.5,'DisplayName','saturated');
plot(ax,r,T.deadline_miss_pct,'-o','Color',col,'LineWidth',lw,'MarkerFaceColor',col,'MarkerSize',ms,'HandleVisibility','off');
xlabel(ax,'Offered rate (eval/s)','FontSize',fsize); ylabel(ax,'1 s deadline-miss rate (%)','FontSize',fsize);
xlim(ax,[0 rmax+2]); ylim(ax,[-3 100]); grid(ax,'on'); ax.GridAlpha=0.25; box(ax,'on'); ax.FontSize=fsize-1;
legend(ax,'Location','east','Box','off','FontSize',fsize-2);
title(ax,'Policy-engine deadline misses (saturation knee ~25-30/s)','FontSize',fsize-1); hold(ax,'off');
exportgraphics(fig,fullfile(here,'exp2_deadline_miss.pdf'),'ContentType','vector');
exportgraphics(fig,fullfile(here,'exp2_deadline_miss.png'),'Resolution',200); close(fig);
end
