function fig_exp2_saturation()
%FIG_EXP2_SATURATION  Policy engine: offered vs achieved eval/s (y=x ideal).
% Reads exp2_evaluator_scaling.csv. The point where achieved stops following
% offered is the saturation region. Self-contained.

% ---- STYLE ----
col=[0.031 0.318 0.612]; col_ideal=[0.6 0.6 0.6];
lw=1.8; ms=6; fsize=11; figsize=[0 0 5.8 3.8];
% ---------------
here=fileparts(mfilename('fullpath'));
T=readtable(fullfile(here,'exp2_evaluator_scaling.csv'));
r=T.offered_rate_eval_s;
fig=figure('Units','inches','Position',figsize,'Color','w'); ax=axes(fig); hold(ax,'on');
plot(ax,[0 max(r)],[0 max(r)],'--','Color',col_ideal,'LineWidth',1.2,'DisplayName','ideal y=x');
plot(ax,r,T.achieved_rate_eval_s,'-o','Color',col,'LineWidth',lw,'MarkerFaceColor',col,'MarkerSize',ms,'DisplayName','achieved');
xlabel(ax,'Offered rate (eval/s)','FontSize',fsize); ylabel(ax,'Achieved rate (eval/s)','FontSize',fsize);
xlim(ax,[0 max(r)+2]); grid(ax,'on'); ax.GridAlpha=0.25; box(ax,'on'); ax.FontSize=fsize-1;
legend(ax,'Location','northwest','Box','off','FontSize',fsize-2);
title(ax,'Policy-engine throughput saturation','FontSize',fsize-1); hold(ax,'off');
exportgraphics(fig,fullfile(here,'exp2_saturation.pdf'),'ContentType','vector');
exportgraphics(fig,fullfile(here,'exp2_saturation.png'),'Resolution',200); close(fig);
end
